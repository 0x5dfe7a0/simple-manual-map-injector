#pragma once

struct map_shellcode_data
{
    void* module_base;
    void* reserved_data;
    volatile bool done;
    HINSTANCE( *load_library )( const char* );
    FARPROC( *get_proc_address )( HMODULE , LPCSTR );
};

struct map_reserved_data
{
    uint64_t module_base;
    uint64_t module_size;
};

void __stdcall map_shellcode( map_shellcode_data* data );

class c_manual_map
{
public:
    uint32_t inject( const wchar_t* process_name , uint8_t* data , size_t size , void* reserved = nullptr , size_t reserved_size = 0 );

private:
    uint32_t find_pid( const wchar_t* name ) const;
    HANDLE find_thread( ) const;
    HANDLE hijack_handle( uint32_t target_pid , ACCESS_MASK access ) const;
    uint64_t alloc( size_t size , uint32_t protect ) const;
    void dealloc( uint64_t addr ) const;
    bool write( uint64_t addr , void* data , size_t size ) const;
    bool protect( uint64_t addr , size_t size , uint32_t flags ) const;

    template < typename t >
    t read( uint64_t addr ) const
    {
        t out {};
        ReadProcessMemory( m_process , reinterpret_cast< void* >( addr ) , &out , sizeof( t ) , nullptr );
        return out;
    }

    uint32_t m_pid = 0;
    HANDLE m_process = nullptr;
    HANDLE m_thread = nullptr;
};