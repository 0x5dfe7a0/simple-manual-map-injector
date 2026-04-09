features:

- handle hijacking -> duplicates existing handle from csrss instead of calling OpenProcess directly
- thread hijacking -> hijacks a waiting thread instead of CreateRemoteThread
- process enumeration via NtQuerySystemInformation
- full pe loader shellcode (relocations, imports, tls, entry point)
- section protection fixup after mapping
- header + shellcode wipe post injection

this is mainly used to load your usermode payload etc inside another process like notepad.exe or obs64.exe this approach is not recommended for injecting into anti cheat protected games and most likely wont work
