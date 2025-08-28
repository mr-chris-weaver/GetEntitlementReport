# Import Module for performing PSafe functions
<#
Pre-reqs:
Asset Management Read
Password Safe Account Management Read
Password Safe Policy Management Read
Password Safe Role management Read
Password Safe System management Read
User Accounts management Read

Using the join object script this script will pull back entitlements, stitch it all together and dump it into a csv 
#>

Import-Module .\REALLYGENERIC.ps1
Import-Module .\Join-Object.ps1
# Import BI cert for authentication
[System.Security.Cryptography.X509Certificates.X509Certificate2]$script:authCert = $cert;
# Authenticate against Psafe API
psafe-signappin

#retrieve all smart rule (read access to all asset and account smart rules is a pre-requisite for this script)
$smartRules= psafe-get "smartrules"

#retrieve all managed systems 
$managedSystems= psafe-get "managedsystems"
#retrieve all password policies
$passwordRules= Psafe-get "passwordrules"

$table=@()
$accounts=@()
# Loop through each smart rule and then each usergroup to show the password safe role applied to the group via smart rule
foreach($smartRule in $smartRules){
    
    $table= psafe-get "smartrules/$($smartRule.SmartRuleID)/ManagedAccounts"
    foreach($object in $table){
        #$object |Add-Member -MemberType NoteProperty -name SmartRuleName -Value $smartRule.Title
        $object |Add-Member -MemberType NoteProperty -name SmartRuleID -Value $smartRule.SmartRuleID
        $systemName = $managedSystems | where ManagedSystemID -EQ $object.ManagedSystemID | Select -ExpandProperty SystemName
        $object |Add-Member -MemberType NoteProperty -name SystemName -Value $systemName
        $passwordPolicy= $passwordRules | where PasswordRuleID -EQ $object.PasswordRuleID | Select -ExpandProperty Name
        $object |Add-Member -MemberType NoteProperty -name PasswordPolicy -Value $passwordPolicy
    } 
    $accounts+= $table 
}

# select properties desired and export the data to a desired repository
#$accounts | select SmartRuleName, AccountName,APIEnabled | ft -AutoSize | Export-Csv -NoTypeInformation C:\Temp\SmartRuleManagedAccounts.csv

$userGroups= psafe-get "usergroups"

$table = @()
$test =@()
$groupPerms=@()
foreach($smartRule in $smartRules){
    
    foreach($usergroup in $userGroups){
        $test= psafe-get "usergroups/$($usergroup.GroupID)/smartrules/$($smartRule.SmartRuleID)/roles"

        if($test -ne $null){
           $table=$test
           $table |Add-Member -MemberType NoteProperty -name SmartRuleName -Value $smartRule.Title
           $table |Add-Member -MemberType NoteProperty -name SmartRuleID -Value $smartRule.SmartRuleID
           $table |Add-Member -MemberType NoteProperty -name UserGroupName -Value $usergroup.Name
           $table |Add-Member -MemberType NoteProperty -name UserGroupID -Value $usergroup.GroupID
           $table |Add-Member -MemberType NoteProperty -name UserGroupType -Value $usergroup.GroupType

           $groupPerms+=$table
        }
    }
}
$report =@()
$report=$groupPerms |Join-Object -JoinType Inner $accounts -On SmartRuleID
$report| Export-Csv -NoTypeInformation .\entitlementreport.csv

PSafe-Post "auth/signout"