#include <include/core.hpp>

typedef NTSTATUS( NTAPI* nt_suspend_t )( HANDLE );
typedef NTSTATUS( NTAPI* nt_resume_t )( HANDLE );
typedef NTSTATUS( NTAPI* nt_duplicate_object_t )( HANDLE , HANDLE , HANDLE , PHANDLE , ACCESS_MASK , ULONG , ULONG );

struct system_thread_info
{
    LARGE_INTEGER kernel_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER create_time;
    ULONG wait_time;
    PVOID start_address;
    CLIENT_ID client_id;
    LONG priority;
    LONG base_priority;
    ULONG context_switches;
    ULONG state;
    ULONG wait_reason;
};

struct system_handle_entry
{
    USHORT process_id;
    USHORT creator_back_trace_index;
    UCHAR object_type_index;
    UCHAR handle_attributes;
    USHORT handle_value;
    PVOID object;
    ULONG granted_access;
};

struct system_handle_information
{
    ULONG handle_count;
    system_handle_entry handles [ 1 ];
};

uint32_t c_manual_map::find_pid( const wchar_t* name ) const
{
    ULONG size = 0;
    NtQuerySystemInformation( SystemProcessInformation , nullptr , 0 , &size );

    if ( !size )
    {
        return 0;
    }

    std::vector< uint8_t > buffer( size );
    auto info = reinterpret_cast< SYSTEM_PROCESS_INFORMATION* >( buffer.data( ) );

    if ( !NT_SUCCESS( NtQuerySystemInformation( SystemProcessInformation , info , size , &size ) ) )
    {
        return 0;
    }

    while ( true )
    {
        if ( info->ImageName.Buffer && info->ImageName.Length > 0 )
        {
            std::wstring image( info->ImageName.Buffer , info->ImageName.Length / sizeof( wchar_t ) );

            if ( _wcsicmp( image.c_str( ) , name ) == 0 )
            {
                return static_cast< uint32_t >( reinterpret_cast< uint64_t >( info->UniqueProcessId ) );
            }
        }

        if ( !info->NextEntryOffset )
        {
            break;
        }

        info = reinterpret_cast< SYSTEM_PROCESS_INFORMATION* >( reinterpret_cast< uint8_t* >( info ) + info->NextEntryOffset );
    }

    return 0;
}

HANDLE c_manual_map::find_thread( ) const
{
    ULONG size = 0;
    NtQuerySystemInformation( SystemProcessInformation , nullptr , 0 , &size );

    if ( !size )
    {
        return nullptr;
    }

    std::vector< uint8_t > buffer( size );
    auto info = reinterpret_cast< SYSTEM_PROCESS_INFORMATION* >( buffer.data( ) );

    if ( !NT_SUCCESS( NtQuerySystemInformation( SystemProcessInformation , info , size , &size ) ) )
    {
        return nullptr;
    }

    while ( true )
    {
        if ( reinterpret_cast< uint64_t >( info->UniqueProcessId ) == m_pid )
        {
            break;
        }

        if ( !info->NextEntryOffset )
        {
            return nullptr;
        }

        info = reinterpret_cast< SYSTEM_PROCESS_INFORMATION* >( reinterpret_cast< uint8_t* >( info ) + info->NextEntryOffset );
    }

    auto threads = reinterpret_cast< system_thread_info* >( reinterpret_cast< uint8_t* >( info ) + sizeof( SYSTEM_PROCESS_INFORMATION ) );

    HANDLE best_handle = nullptr;
    bool found_ideal = false;

    for ( ULONG idx = 0; idx < info->NumberOfThreads && !found_ideal; ++idx )
    {
        if ( threads [ idx ].state != 5 )
        {
            continue;
        }

        auto thread_id = static_cast< uint32_t >( reinterpret_cast< uint64_t >( threads [ idx ].client_id.UniqueThread ) );
        auto thread_handle = OpenThread( THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT , FALSE , thread_id );

        if ( !thread_handle || thread_handle == INVALID_HANDLE_VALUE )
        {
            continue;
        }

        if ( threads [ idx ].wait_reason == 6 )
        {
            if ( best_handle )
            {
                CloseHandle( best_handle );
            }

            best_handle = thread_handle;
            found_ideal = true;
        }
        else if ( !best_handle )
        {
            best_handle = thread_handle;
        }
        else
        {
            CloseHandle( thread_handle );
        }
    }

    return best_handle;
}

HANDLE c_manual_map::hijack_handle( uint32_t target_pid , ACCESS_MASK access ) const
{
    auto ntdll = GetModuleHandleA( "ntdll.dll" );
    auto nt_duplicate_object = reinterpret_cast< nt_duplicate_object_t >( GetProcAddress( ntdll , "NtDuplicateObject" ) );

    if ( !nt_duplicate_object )
    {
        return nullptr;
    }

    ULONG size = sizeof( system_handle_information ) + ( sizeof( system_handle_entry ) * 0x10000 );
    std::vector< uint8_t > buffer;
    NTSTATUS status = 0;

    for ( int attempt = 0; attempt < 8; ++attempt )
    {
        buffer.resize( size );
        status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 16 ) , buffer.data( ) , size , &size );

        if ( NT_SUCCESS( status ) )
        {
            break;
        }

        size *= 2;
    }

    if ( !NT_SUCCESS( status ) )
    {
        return nullptr;
    }

    auto handle_info = reinterpret_cast< system_handle_information* >( buffer.data( ) );
    uint32_t csrss_pid = find_pid( L"csrss.exe" );
    HANDLE result = nullptr;

    for ( int pass = 0; pass < 2 && !result; ++pass )
    {
        for ( ULONG idx = 0; idx < handle_info->handle_count; ++idx )
        {
            auto& entry = handle_info->handles [ idx ];

            if ( entry.object_type_index != 0x7 )
            {
                continue;
            }

            if ( entry.process_id == GetCurrentProcessId( ) || entry.process_id == target_pid )
            {
                continue;
            }

            if ( ( entry.granted_access & access ) != access )
            {
                continue;
            }

            if ( pass == 0 && entry.process_id != csrss_pid )
            {
                continue;
            }

            auto source_handle = OpenProcess( PROCESS_DUP_HANDLE , FALSE , entry.process_id );

            if ( !source_handle || source_handle == INVALID_HANDLE_VALUE )
            {
                continue;
            }

            HANDLE duped_handle = nullptr;
            nt_duplicate_object( source_handle , reinterpret_cast< HANDLE >( static_cast< uint64_t >( entry.handle_value ) ) , GetCurrentProcess( ) , &duped_handle , 0 , 0 , DUPLICATE_SAME_ACCESS );
            CloseHandle( source_handle );

            if ( !duped_handle )
            {
                continue;
            }

            if ( GetProcessId( duped_handle ) != target_pid )
            {
                CloseHandle( duped_handle );
                continue;
            }

            result = duped_handle;
            break;
        }
    }

    return result;
}

uint64_t c_manual_map::alloc( size_t size , uint32_t prot ) const
{
    return reinterpret_cast< uint64_t >( VirtualAllocEx( m_process , nullptr , size , MEM_COMMIT | MEM_RESERVE , prot ) );
}

void c_manual_map::dealloc( uint64_t addr ) const
{
    VirtualFreeEx( m_process , reinterpret_cast< void* >( addr ) , 0 , MEM_RELEASE );
}

bool c_manual_map::write( uint64_t addr , void* data , size_t size ) const
{
    return WriteProcessMemory( m_process , reinterpret_cast< void* >( addr ) , data , size , nullptr );
}

bool c_manual_map::protect( uint64_t addr , size_t size , uint32_t flags ) const
{
    DWORD old = 0;
    return VirtualProtectEx( m_process , reinterpret_cast< void* >( addr ) , size , flags , &old );
}

uint32_t c_manual_map::inject( const wchar_t* process_name , uint8_t* data , size_t size , void* reserved , size_t reserved_size )
{
    m_pid = find_pid( process_name );

    if ( !m_pid )
    {
        return 0x1000;
    }

    auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( data );

    if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
    {
        return 0x1001;
    }

    auto nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( data + dos->e_lfanew );

    if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
    {
        return 0x1002;
    }

    m_process = hijack_handle( m_pid , PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION );

    if ( !m_process )
    {
        return 0x1003;
    }

    auto ntdll = GetModuleHandleA( "ntdll.dll" );
    auto suspend = reinterpret_cast< nt_suspend_t >( GetProcAddress( ntdll , "NtSuspendProcess" ) );
    auto resume = reinterpret_cast< nt_resume_t >( GetProcAddress( ntdll , "NtResumeProcess" ) );

    if ( !suspend || !resume )
    {
        CloseHandle( m_process );
        return 0x1003;
    }

    suspend( m_process );

    uint32_t result = 0;
    uint64_t image_base = 0;
    uint64_t reserved_addr = 0;
    uint64_t shellcode_data_addr = 0;
    uint64_t shellcode_addr = 0;
    uint64_t stub_addr = 0;

    m_thread = find_thread( );

    if ( !m_thread )
    {
        result = 0x1004;
        goto cleanup;
    }

    CONTEXT original_ctx;
    original_ctx.ContextFlags = CONTEXT_FULL;

    if ( !GetThreadContext( m_thread , &original_ctx ) )
    {
        result = 0x1004;
        goto cleanup;
    }

    image_base = alloc( nt_headers->OptionalHeader.SizeOfImage , PAGE_EXECUTE_READWRITE );

    if ( !image_base )
    {
        result = 0x1005;
        goto cleanup;
    }

    write( image_base , data , 0x1000 );

    {
        auto section = IMAGE_FIRST_SECTION( nt_headers );

        for ( int idx = 0; idx < nt_headers->FileHeader.NumberOfSections; idx++ , section++ )
        {
            if ( !section->SizeOfRawData )
            {
                continue;
            }

            write( image_base + section->VirtualAddress , data + section->PointerToRawData , section->SizeOfRawData );
        }
    }

    if ( reserved && reserved_size )
    {
        reserved_addr = alloc( reserved_size , PAGE_READWRITE );

        if ( !reserved_addr )
        {
            result = 0x1008;
            goto cleanup;
        }

        write( reserved_addr , reserved , reserved_size );
    }
    else
    {
        map_reserved_data rd {};
        rd.module_base = image_base;
        rd.module_size = nt_headers->OptionalHeader.SizeOfImage;

        reserved_addr = alloc( sizeof( map_reserved_data ) , PAGE_READWRITE );

        if ( !reserved_addr )
        {
            result = 0x1008;
            goto cleanup;
        }

        write( reserved_addr , &rd , sizeof( map_reserved_data ) );
    }

    {
        map_shellcode_data sd {};
        sd.module_base = reinterpret_cast< void* >( image_base );
        sd.reserved_data = reinterpret_cast< void* >( reserved_addr );
        sd.done = false;
        sd.load_library = LoadLibraryA;
        sd.get_proc_address = GetProcAddress;

        shellcode_data_addr = alloc( sizeof( map_shellcode_data ) , PAGE_READWRITE );

        if ( !shellcode_data_addr )
        {
            result = 0x1012;
            goto cleanup;
        }

        write( shellcode_data_addr , &sd , sizeof( map_shellcode_data ) );
    }

    shellcode_addr = alloc( 0x1000 , PAGE_EXECUTE_READWRITE );

    if ( !shellcode_addr )
    {
        result = 0x1014;
        goto cleanup;
    }

    write( shellcode_addr , map_shellcode , 0x1000 );

    {
        uint8_t stub [ ] =
        {
            0x48 , 0x89 , 0xE0 ,
            0x48 , 0x83 , 0xE4 , 0xF0 ,
            0x50 ,
            0x48 , 0x83 , 0xEC , 0x28 ,
            0x48 , 0xB9 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 ,
            0x48 , 0xB8 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 ,
            0xFF , 0xD0 ,
            0xEB , 0xFE
        };

        *reinterpret_cast< uint64_t* >( &stub [ 14 ] ) = shellcode_data_addr;
        *reinterpret_cast< uint64_t* >( &stub [ 24 ] ) = shellcode_addr;

        stub_addr = alloc( sizeof( stub ) , PAGE_EXECUTE_READWRITE );

        if ( !stub_addr )
        {
            result = 0x1016;
            goto cleanup;
        }

        write( stub_addr , stub , sizeof( stub ) );

        CONTEXT hijacked_ctx = original_ctx;
        hijacked_ctx.Rip = stub_addr;
        SetThreadContext( m_thread , &hijacked_ctx );
        ResumeThread( m_thread );

        for ( ;; )
        {
            auto check = read< map_shellcode_data >( shellcode_data_addr );

            if ( check.done )
            {
                break;
            }

            Sleep( 1 );
        }

        SuspendThread( m_thread );
        SetThreadContext( m_thread , &original_ctx );

        std::vector< uint8_t > stub_zero( sizeof( stub ) , 0 );
        write( stub_addr , stub_zero.data( ) , stub_zero.size( ) );
    }

    {
        auto section = IMAGE_FIRST_SECTION( nt_headers );

        for ( int idx = 0; idx < nt_headers->FileHeader.NumberOfSections; idx++ , section++ )
        {
            DWORD section_prot = PAGE_READONLY;
            auto characteristics = section->Characteristics;

            if ( characteristics & IMAGE_SCN_MEM_EXECUTE )
            {
                section_prot = ( characteristics & IMAGE_SCN_MEM_WRITE ) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            }
            else if ( characteristics & IMAGE_SCN_MEM_WRITE )
            {
                section_prot = PAGE_READWRITE;
            }

            protect( image_base + section->VirtualAddress , section->Misc.VirtualSize , section_prot );
        }
    }

    {
        std::vector< uint8_t > empty( nt_headers->OptionalHeader.SizeOfHeaders , 0 );
        write( image_base , empty.data( ) , empty.size( ) );

        std::vector< uint8_t > zero( 0x1000 , 0 );
        write( shellcode_addr , zero.data( ) , zero.size( ) );
    }

cleanup:

    if ( shellcode_data_addr )
    {
        dealloc( shellcode_data_addr );
    }

    if ( shellcode_addr )
    {
        dealloc( shellcode_addr );
    }

    if ( stub_addr )
    {
        dealloc( stub_addr );
    }

    if ( result )
    {
        if ( reserved_addr )
        {
            dealloc( reserved_addr );
        }

        if ( image_base )
        {
            dealloc( image_base );
        }
    }

    resume( m_process );

    if ( m_thread )
    {
        CloseHandle( m_thread );
    }

    CloseHandle( m_process );

    m_thread = nullptr;
    m_process = nullptr;

    return result;
}

#pragma runtime_checks( "" , off )
#pragma optimize( "" , off )

void __stdcall map_shellcode( map_shellcode_data* data )
{
    auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( data->module_base );
    auto nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< uint8_t* >( data->module_base ) + dos->e_lfanew );
    auto entry = reinterpret_cast< int32_t( * )( void* , uint32_t , void* ) >( reinterpret_cast< uint64_t >( data->module_base ) + nt_headers->OptionalHeader.AddressOfEntryPoint );

    auto reloc_dir = nt_headers->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
    auto import_dir = nt_headers->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ];
    auto delta = reinterpret_cast< uint64_t >( data->module_base ) - nt_headers->OptionalHeader.ImageBase;

    if ( reloc_dir.Size )
    {
        auto block = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( data->module_base ) + reloc_dir.VirtualAddress );
        auto end = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( block ) + reloc_dir.Size );

        while ( block < end && block->SizeOfBlock )
        {
            auto count = ( block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( uint16_t );
            auto items = reinterpret_cast< uint16_t* >( block + 1 );

            for ( DWORD idx = 0; idx < count; ++idx )
            {
                if ( ( items [ idx ] >> 12 ) == IMAGE_REL_BASED_DIR64 )
                {
                    auto patch_addr = reinterpret_cast< uint64_t* >( reinterpret_cast< uint64_t >( data->module_base ) + block->VirtualAddress + ( items [ idx ] & 0xFFF ) );
                    *patch_addr += delta;
                }
            }

            block = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( block ) + block->SizeOfBlock );
        }
    }

    if ( import_dir.Size )
    {
        auto descriptor = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( reinterpret_cast< uint64_t >( data->module_base ) + import_dir.VirtualAddress );

        while ( descriptor->Name )
        {
            auto module_name = reinterpret_cast< char* >( reinterpret_cast< uint64_t >( data->module_base ) + descriptor->Name );
            auto module_handle = data->load_library( module_name );

            if ( module_handle )
            {
                auto original_thunk = reinterpret_cast< IMAGE_THUNK_DATA* >( reinterpret_cast< uint64_t >( data->module_base ) + descriptor->OriginalFirstThunk );
                auto first_thunk = reinterpret_cast< IMAGE_THUNK_DATA* >( reinterpret_cast< uint64_t >( data->module_base ) + descriptor->FirstThunk );

                while ( original_thunk->u1.AddressOfData )
                {
                    FARPROC function = nullptr;

                    if ( original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
                    {
                        function = data->get_proc_address( module_handle , reinterpret_cast< const char* >( original_thunk->u1.Ordinal & 0xFFFF ) );
                    }
                    else
                    {
                        auto import_name = reinterpret_cast< IMAGE_IMPORT_BY_NAME* >( reinterpret_cast< uint64_t >( data->module_base ) + original_thunk->u1.AddressOfData );
                        function = data->get_proc_address( module_handle , import_name->Name );
                    }

                    if ( function )
                    {
                        first_thunk->u1.Function = reinterpret_cast< uint64_t >( function );
                    }

                    ++original_thunk;
                    ++first_thunk;
                }
            }

            ++descriptor;
        }
    }

    auto tls_dir = nt_headers->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_TLS ];

    if ( tls_dir.Size )
    {
        auto tls = reinterpret_cast< IMAGE_TLS_DIRECTORY* >( reinterpret_cast< uint64_t >( data->module_base ) + tls_dir.VirtualAddress );
        auto callbacks = reinterpret_cast< PIMAGE_TLS_CALLBACK* >( tls->AddressOfCallBacks );

        if ( callbacks )
        {
            while ( *callbacks )
            {
                ( *callbacks )( data->module_base , DLL_PROCESS_ATTACH , nullptr );
                ++callbacks;
            }
        }
    }

    entry( data->module_base , DLL_PROCESS_ATTACH , data->reserved_data );
    data->done = true;
}