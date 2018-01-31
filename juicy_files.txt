rule ntds_file : usernames hashed_passwords active_directory windows passwords
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find the ntds.dit file"
    strings:
        $filemagic = {ef cd ab 89}
        $content_string = "Admin-Display-Name" nocase wide
        $content_string2 = "Address-Entry-Display-Table-MSDOS" nocase wide
        $content_string3 = "nTDSDSA-Display" nocase wide
        $content_string4 = "MSysObjects" nocase ascii
        $content_string5 = "ObjidTable" nocase ascii
    condition:
        ($filemagic at 4) and (int32(12) == 0 or int32(12) == 1) and all of ($content_*)
}

rule hive_file : usernames hashed_passwords registry windows passwords
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find registry hive files like system/security/sam"
    strings:
        $filemagic = "regf"
        $filemagicbin = "hbin"
        $content_string = "ROOT"
    condition:
        $filemagic at 0 and $filemagicbin at 4096 and $content_string
        
}

rule shadow_file : usernames hashed_passwords linux passwords
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find shadow files"
    strings:
        $rootline = /root:.:\d+?:\d+?:\d+?:\d+?:/ nocase
        $hashline = /:\$\d\$/
        $hashtype_md5 = ":$1$"
        $hashtype_blowfish = ":$2a$"
        $hashtype_blowfish2 = ":$2y$"
        $hashtype_sha256 = ":$5$"
        $hashtype_sha512 = ":$6$"
    condition:
        $rootline and $hashline and (1 of ($hashtype_*))
}

rule tomcat_file : usernames plain_passwords passwords
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find tomcat config file with plaintext passwords"
    strings:
        $xml_ident = "<tomcat-users>" nocase
        $xml_ident2 = "</tomcat-users>" nocase
        $roles = "<role rolename=" nocase
        $password_string = "username=" nocase
        $password_string2 = "password=" nocase
        $password_string3 = "roles=" nocase
    condition:
        all of them
}

rule mysql_file : usernames plain_passwords passwords
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find mysql config file with plaintext passwords"
    strings:
        $section_header = "[client]\n" nocase
        $section_header2 = "[mysqld]\n" nocase
        $content_data = /port.{,10}?=/ nocase
        $content_data2 = /socket.{,10}?=/ nocase
        $content_data3 = /max_connections.{,10}?=/ nocase 
        $creds_user = /user.{,10}?=/ nocase
        $creds_password = /password.{,10}?=/ nocase
    condition:
        all of them
}

rule unencrypted_private_key : plain_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find unencrypted private keys"
    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $content2 = "encrypted" nocase
    condition:
        $content at 0 and not $content2
}

rule encrypted_private_key : encrypted_privatekey privatekey keycontainer
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find encrypted private keys"
    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $content2 = "encrypted" nocase
    condition:
        $content at 0 and $content2
}

rule keepass_file : keycontainer keepass
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find keepass containers"
    strings:
        $filemagic_primary = {03 D9 A2 9A}
        $filemagic_secondary = {(67 | 65 | 66 | 55) FB 4B B5}
    condition:
        $filemagic_primary at 0 and $filemagic_secondary at 4
}

rule jks_file : keycontainer java_keystore
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find java keystore containers"
    strings:
        $filemagic = {fe ed fe ed 00 00 00 02}
    condition:
        $filemagic at 0
}

rule encrypted_ppk_file : keycontainer putty encrypted_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find encrypted putty ppk files"
    strings:
        $content = "PuTTY-User-Key-File-2" nocase
        $content2 = "Encryption" nocase
        $content3 = "Private-Lines" nocase
        $content4 = "none" nocase
    condition:
        $content at 0 and $content2 and $content3 and not $content4
}

rule ppk_file : keycontainer putty plain_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find putty ppk files"
    strings:
        $content = "PuTTY-User-Key-File-2" nocase
        $content2 = "Encryption" nocase
        $content3 = "Private-Lines" nocase
        $content4 = "none" nocase
    condition:
        $content at 0 and $content2 and $content3 and $content4
}

rule minidump_file : memory windows
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find memory dump files"
    strings:
        $header = "MDMP"
        $formatversion = {93 a7}
    condition:
        $header at 0 and $formatversion at 4
}

rule crashdump_file : memory windows
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find memory dump files"
    strings:
        $header = "PAGE"
        $header2 = "DUMP"
    condition: //might not work due to int32() on filesize, should be int64, but not available
        $header at 0 and $header2 at 4 and (uint32(0xf88) == 1 or uint32(0xf88) == 2) and int32(0xfa0) >= filesize
}

rule crashdump64_file : memory windows
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find memory dump files"
    strings:
        $header = "PAGE"
        $header2 = "DU64"
    condition: //might not work due to int32() on filesize, should be int64, but not available
        $header at 0 and $header2 at 4 and (uint32(0xf98) == 1 or uint32(0xf98) == 2) and int32(0xfa0) >= filesize
}

rule vmdk_file : virtualdisk
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find vmdk files"
    strings:
        $filemagic = {4b 44 4d} //KDM
        $header = "# Disk DescriptorFile"
        $header2 = "version="
        $header3 = "CID="
        $header4 = "parentCID="
        $header5 = "createType="
        $header6 = "# Extent description"
    condition:
        $filemagic at 0 and (all of ($header*))
}

rule gpp_file : passwords plain_password
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find gpp files"
    strings:
        $content1 = "<?xml" nocase
        $content2 = "<user" nocase
        $content3 = "cpassword=" nocase
        $content4 = "username=" nocase
        $content5 = "clsid=" nocase
        $content6 = "</user>" nocase
    condition:
        all of them
}

rule sql_dump : passwords dbdump {
    meta:
        author = "ydklijnsma https://blog.0x3a.com"
        description = "Looks at sql dump file pattern"

    strings:
        $dump_header_regex = /-- [a-zA-Z0-9]+\s?SQL\s?[Dd]ump\s?/i

        $dump_string_createtableifexists = "CREATE TABLE IF NOT EXISTS"
        $dump_string_droptableifexists = "DROP TABLE IF EXISTS "
        $dump_string_createtable = "CREATE TABLE "

        $insert_into = "INSERT INTO "

    condition:
        $dump_header_regex at 0 and
            (2 of ($dump_string_*)) and
                #insert_into >= 1
}

rule idapro_database {
	meta:
		author = "ydklijnsma https://blog.0x3a.com/"
		description = "Finds IDA pro IDB databases"
	
	strings:
		$magic = { 49 44 41 ?? }
		$btree_str = "B-tree"

	condition:
		$magic at 0 and $btree_str

}
