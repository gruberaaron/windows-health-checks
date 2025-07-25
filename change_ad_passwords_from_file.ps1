#
# Written by Aaron Gruber
#
# ToDo
#   1.Add exception handling in loop so Write-Host does not execute of error is encountered.
#
# Changelog
# [8/29/2024]
#   Inital script creation and validation of success
#
###################################################################################################


#   Set path to CSV file. File must have headers of "Username" and "Password"
#   Change 'PathToFile' to desired file path.
$inputFile = import-csv -Path 'C:\temp\AccountPW-4.csv'


#   Loop through file and perform the following actions:
#       *Set user password
#       *Set user account password to never expire.
#       *Output to screen "User <username> password has been changed to <password>""
ForEach($i in $inputFile){
    $username = $i.Username
    $password = $i.Password
    Set-ADAccountPassword -Identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
    Set-ADUser -Identity $username -PasswordNeverExpires $true
    Write-Host "$($username),$($password)"
}
