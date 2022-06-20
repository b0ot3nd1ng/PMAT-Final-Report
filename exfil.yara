rule Exfil_YARA {
    
    meta: 
        last_updated = "2022-06-20"
        author = "b0ot3nd1ng"
        description = "A sample Yara rule for Siko Mode Exfiltrator Malware"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "passwrd.txt" ascii
        $string2 = "nim"
        $PE_magic_byte = "MZ"

    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and //if it finds MZ at first byte
        ($string1 and $string2)

}
