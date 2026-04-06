#include <include/core.hpp>

int main( )
{
    // method 1 -> stream payload from auth ( recommended bc it never touches the disk ) 
    // auto payload = auth::download_file( "however ur auth expects to validate the response" );

    // method 2 -> read payload from disk
	std::ifstream file( "C:\\example.dll" , std::ios::binary | std::ios::ate ); // replace this with ur path to the dll u want to inject

    if ( !file.is_open( ) )
    {
        return 1;
    }

    auto size = file.tellg( );
    file.seekg( 0 );

    std::vector< uint8_t > payload( size );
    file.read( reinterpret_cast< char* >( payload.data( ) ) , size );
    file.close( );

    auto result = g_manual_map->inject( L"obs64.exe" , payload.data( ) , payload.size( ) );
    // MessageBoxA( nullptr , std::to_string( result ).c_str( ) , nullptr , 0 );

    return result;
}