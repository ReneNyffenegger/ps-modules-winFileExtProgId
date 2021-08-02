#
#  V0.1
#
set-strictMode -version 3

new-psDrive -psProvider registry -root HKEY_CLASSES_ROOT -name HKCR

function open-or-edit-command-of-progId { # «internal» function

   param (
     [string] $progId
   )

   $rn_progId = "hkcr:\$progId"

   if (! (test-path $rn_progId)) {
      return (get-textInConsoleErrorColor "$rn_progId does not exist")
   }

   $rn_progId_shell_open_command = "$rn_progId\shell\open\command"

   if (! (test-path $rn_progId_shell_open_command)) {
      $rn_progId_shell_edit_command = "$rn_progId\shell\edit\command"

      if (! (test-path $rn_progId_shell_edit_command)) {
         return (get-textInConsoleErrorColor "Neither $rn_progId_shell_open_command nor $rn_progId_shell_edit_command exists")
      }
      return (get-itemProperty $rn_progId_shell_edit_command).'(default)'
   }

   return (get-itemProperty $rn_progId_shell_open_command).'(default)'
}

function show-regKey_SoftwareClasses_ { # «internal» function
   param (
     [string] $regRoot,
     [string] $ext
   )

   $rn_SoftwareClasses = "$regRoot`:\Software\Classes\$ext"

   if (test-path $rn_SoftwareClasses) {
      write-host "$rn_SoftwareClasses exists"

      $rk_SoftwareClasses = get-item $rn_SoftwareClasses

      $SoftwareClasses_defaultValue = $rk_SoftwareClasses.GetValue('')

      if ($SoftwareClasses_defaultValue -ne $null) {
         write-host ('   Default value {0,-23} -> {1}' -f $SoftwareClasses_defaultValue, (open-or-edit-command-of-progId $SoftwareClasses_defaultValue))
      }

      $rn_SoftwareClasses_shell_open_command = "$rn_SoftwareClasses\Shell\Open\Command"
      if (test-path $rn_SoftwareClasses_shell_open_command) {
         write-host "$rn_SoftwareClasses_shell_open_command exists"

         $SoftwareClasses_shell_open_command_defaultValue = (get-itemProperty $rn_SoftwareClasses_shell_open_command).'(default)'
         write-host ('   Default value {0,-23} -> {1}' -f $SoftwareClasses_shell_open_command_defaultValue, $SoftwareClasses_shell_open_command_defaultValue)

      }
   }
   else {
      write-host "$rn_SoftwareClasses does not exist"
   }

}

function show-winFileExtAssociation {

   param (
     [string] $ext
   )

   if ($ext -notMatch '^\.') {
      $ext = ".$ext"
   }


   $rn_explorerFileExts = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext"

   if (test-path $rn_explorerFileExts) {

      write-host "$rn_explorerFileExts exists"

      # -------------------------- UserChoice

      $rn_explorerFileExts_userChoice = "$rn_explorerFileExts\UserChoice"

      if (test-path $rn_explorerFileExts_userChoice) {

         write-host "$rn_explorerFileExts_userChoice exists"

         $assoc = (get-itemProperty $rn_explorerFileExts_userChoice -errorAction silentlyContinue).ProgId
         $hash  = (get-itemProperty $rn_explorerFileExts_userChoice -errorAction silentlyContinue).Hash

         write-host("   assoc = {0,-29} -> {1}" -f $assoc, ($(open-or-edit-command-of-progId $assoc)))
         write-host "   hash  = $hash"
         write-host ''

      }
      else {
         write-host "$rn_explorerFileExts_userChoice does not exist"
      }

      # --------------------------- OpenWithList

      $rn_explorerFileExts_openWithList = "$rn_explorerFileExts\OpenWithList"

      if (test-path $rn_explorerFileExts_openWithList) {

         write-host "$rn_explorerFileExts_openWithList exists"

         $rk_explorerFileExts_openWithList = get-item $rn_explorerFileExts_openWithList

         $mru_list_txt = $rk_explorerFileExts_openWithList.GetValue('MRUList')

         if ($mru_list_txt -eq $null) {
             write-host "    MRU List does not exists"
         }
         else {
            write-host "   MRUList: $mru_list_txt"
            $mru_list_ary = $mru_list_txt.ToCharArray()

            foreach ($mru_elem in $mru_list_ary) {
                write-host ('        {0,-2}: {1}' -f $mru_elem, $rk_explorerFileExts_openWithList.GetValue($mru_elem))
            }
         }

#        foreach ($openWithName in $rk_explorerFileExts_openWithList.GetValueNames()) {
#            write-host ('   {0,-10} = {1}' -f $openWithName, $rk_explorerFileExts_openWithList.GetValue($openWithName))
#        }

      }
      else {
         write-host "$rn_ExplorerFileExts_openWithList does not exist"
      }

      # ---------------------------

      $rn_explorerFileExts_openWithProgids = "$rn_explorerFileExts\OpenWithProgids"

      if (test-path $rn_explorerFileExts_openWithProgids) {

         write-host "$rn_explorerFileExts_openWithProgids exists"

         $rk_explorerFileExts_openWithProgIds = get-item $rn_explorerFileExts_openWithProgids

         foreach ($openWithProgIdName in $rk_explorerFileExts_openWithProgIds.GetValueNames()) {
             $type = $rk_explorerFileExts_openWithProgIds.GetValueKind($openWithProgIdName)

             if ($type -ne [Microsoft.Win32.RegistryValueKind]::None) {
                write-host "    Unepxected type!"
             }

             write-host ('    {0,-36} -> {1}' -f $openWithProgIdName, (open-or-edit-command-of-progId $openWithProgIdName))
         }

      }
      else {
         write-host "$rn_ExplorerFileExts_openWithProgids does not exist"
      }


   }
   else {
       write-host "$rn_ExplorerFileExts does not exist"
   }

   show-regKey_SoftwareClasses_ HKCU $ext
   show-regKey_SoftwareClasses_ HKLM $ext

}

function set-winFileExtAssociation {

   #
   #  Copied from https://github.com/DanysysTeam/PS-SFTA (and slightly edited by me)
   #

   #
   #   set-winFileExtAssociation  png PBrush                   # associate with MS Paint
   #
   #   set-winFileExtAssociation .sql applications\code.exe
   #   set-winFileExtAssociation  sql applications\code.exe
   #

  param (
    [parameter(mandatory = $true)] [String] $ext,
    [parameter(mandatory = $true)] [String] $ProgId
  )


   if ($ext -notMatch '^\.') {
      $ext = ".$ext"
   }


  function local:Write-ExtensionKeys {

     param (
        [Parameter( Position = 0, Mandatory = $True )] [String] $ProgId,
        [Parameter( Position = 1, Mandatory = $True )] [String] $ext,
        [Parameter( Position = 2, Mandatory = $True )] [String] $ProgHash
     )

     $keyPath = "hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"

     if (test-path $keyPath) {

      #
      # Delete the userChoice key
      #
      # For a reason, removing the key with
      #    remove-item $keyPath
      # failed (sometimes?) with the error
      #    remove-item : Cannot delete a subkey tree because the subkey does not exist.
      #
      # Therefore, the key is deleted somewhat cumbersomly with the helpful
      # code that I found at
      #    https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/deleting-registry-keys-that-can-t-be-deleted
      #
        $parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext", $true)
        $parent.DeleteSubKey('UserChoice', $true)
        $parent.Close()

     }

     $null = new-item $keyPath -force
     set-itemProperty $keyPath Hash   $progHash
     set-itemProperty $keyPath ProgId $progId
   }

   function local:get-userExperienceStringFromShell32 {

#     [OutputType([string])]

      $path_shell32_dll          = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
      $fileStream                = [System.IO.File]::Open($path_shell32_dll, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)

      $binaryReader              = new-object System.IO.BinaryReader($fileStream)
     [byte[]] $shell32_dll_bytes = $binaryReader.ReadBytes(5mb)
      $fileStream.Close()

      $dataString                = [Text.Encoding]::Unicode.GetString($shell32_dll_bytes)

      $pos_start                 = $dataString.IndexOf('User Choice set via Windows User Experience')
      $pos_end                   = $dataString.IndexOf("}", $pos_start)

      return $dataString.Substring($pos_start, $pos_end - $pos_start + 1)
  }



  function local:get-hexDateTime {

#   [OutputType([string])]

    $now         = [DateTime]::Now
    $dateTime    = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
#   $dateTime    = get-date

    $fileTime    = $dateTime.ToFileTime()
    $hi          = ($fileTime -shr 32)
    $low         = ($fileTime -band 0xFFFFFFFFL)
    $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
    Write-Output $dateTimeHex
  }

  function calculate-MShash {
    [CmdletBinding()]
    param (
      [Parameter( Position = 0, Mandatory = $True )] [string] $BaseInfo
    )


    function local:Get-ShiftRight {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)] [long] $iValue,
        [Parameter( Position = 1, Mandatory = $true)] [int ] $iCount
      )

      if ($iValue -band 0x80000000) {
#       Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
        return       (( $iValue -shr $iCount) -bxor 0xFFFF0000)
      }
      else {
#       Write-Output  ($iValue -shr $iCount)
        return ($iValue -shr $iCount)
      }
    }


    function local:Get-Long {
      param (
        [parameter( position = 0, mandatory = $true)] [byte[]] $bytes,
        [parameter( position = 1)] [int] $index = 0
      )

      return       ([BitConverter]::ToInt32($bytes, $index))
    }


    function local:Convert-Int32 {
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        $Value
      )

      [byte[]] $bytes = [BitConverter]::GetBytes($Value)
      return [BitConverter]::ToInt32( $bytes, 0)
    }

    [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo)
    $bytesBaseInfo += 0x00, 0x00

    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)

    $lengthBase = ($baseInfo.Length * 2) + 2
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
    $base64Hash = ""

    if ($length -gt 1) {

      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0; R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0) }

      $map.CACHE    = 0
      $map.OUTHASH1 = 0
      $map.PDATA    = 0
      $map.MD51     = (((Get-Long $bytesMD5  ) -bor 1) + 0x69FB0000L)
      $map.MD52     = (( Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
      $map.INDEX    = Get-ShiftRight ($length - 2) 1
      $map.COUNTER  = $map.INDEX + 1

      while ($map.COUNTER) {
        $map.R0       = Convert-Int32 ((Get-Long $bytesBaseInfo  $map.PDATA) + [long]$map.OUTHASH1)
        $map.R1[0]    = Convert-Int32 ( Get-Long $bytesBaseInfo ($map.PDATA  +  4                ))

        $map.PDATA    = $map.PDATA + 8

        $map.R2[0]    = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
        $map.R2[1]    = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
        $map.R3       = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
        $map.R4[0]    = Convert-Int32 ($map.R3 + $map.R1[0])
        $map.R5[0]    = Convert-Int32 ($map.CACHE + $map.R3)
        $map.R6[0]    = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
        $map.R6[1]    = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
        $map.CACHE    = ([long]$map.OUTHASH2)
        $map.COUNTER  = $map.COUNTER - 1
      }

      [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 0)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 4)

      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0; R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0) }

      $map.CACHE    = 0
      $map.OUTHASH1 = 0
      $map.PDATA    = 0
      $map.MD51     = ((Get-Long $bytesMD5) -bor 1)
      $map.MD52     = ((Get-Long $bytesMD5 4) -bor 1)
      $map.INDEX    = Get-ShiftRight ($length - 2) 1
      $map.COUNTER  = $map.INDEX + 1

      while ($map.COUNTER) {
          $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
          $map.PDATA    = $map.PDATA + 8
          $map.R1[0]    = Convert-Int32 ($map.R0 * [long]$map.MD51)
          $map.R1[1]    = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
          $map.R2[0]    = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
          $map.R2[1]    = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
          $map.R3       = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
          $map.R4[0]    = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
          $map.R4[1]    = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
          $map.R5[0]    = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
          $map.R5[1]    = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
          $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
          $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3)
          $map.CACHE    = ([long]$map.OUTHASH2)
          $map.COUNTER  = $map.COUNTER - 1
        }

        $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 8)

        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 12)

        [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        $hashValue1 = ((Get-Long $outHash  8) -bxor (Get-Long $outHash  ))
        $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))

        $buffer = [BitConverter]::GetBytes($hashValue1)
        $buffer.CopyTo($outHashBase, 0)

        $buffer = [BitConverter]::GetBytes($hashValue2)
        $buffer.CopyTo($outHashBase, 4)
        $base64Hash = [Convert]::ToBase64String($outHashBase)
      }

      Write-Output $base64Hash
   }

   $userSid = ((new-object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()

   $userExperience = get-userExperienceStringFromShell32
   $userDateTime   = get-hexDateTime

   $progHash = calculate-MShash ("$ext$userSid$ProgId$userDateTime$userExperience".ToLower())

   Write-ExtensionKeys $ProgId $ext $progHash

   $rn_sw_cl_ext = "hkcu:\Software\Classes\$ext"
   if (test-path $rn_sw_cl_ext) {

      $rk_sw_cl_ext = get-item $rn_sw_cl_ext
      $hkcu_sw_cl_ext_def_value = $rk_sw_cl_ext.GetValue('')

      if ($hkcu_sw_cl_ext_def_value -ne $null) {
         write-textInConsoleWarningColor "$rn_sw_cl_ext exists with a default value which might cause problems with this association"
      }
   }
}
