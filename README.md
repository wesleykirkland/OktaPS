# OktaPS
Okta API PowerShell Module, to use the module you must run Set-OktaConfig like the below example. If you need to connect to a Preview org add -Preview
Set-OktaConfig -Token YourAPIToken -OktaOrg youroktaorg

Currently Implemented Functions
  
Add-OktaGroupMember
Add-OktaIdentityProviderGroup
Add-OktaUserSchemaProperty
Convert-UnixTimeToDateTime
Get-OktaAPILimit
Get-OktaGroup
Get-OktaGroupApplicationAssignment
Get-OktaGroupMembers
Get-OktaGroups
Get-OktaIdentityProvider
Get-OktaIdentityProviders
Get-OktaUser
Get-OktaUserAvailableFactors
Get-OktaUserAvailableFactorsSecurityQuestion
Get-OktaUserEnrolledFactors
Get-OktaUserFactor
Get-OktaUserGroups
Get-OktaUsers
Get-OktaUserSchema
Get-OktaUserSchemaAll
Get-OktaUserWhoAmI
Invoke-OktaPagedMethod
New-OktaGroup
Remove-OktaGroup
Remove-OktaGroupMember
Remove-OktaIdentityProviderGroup
Remove-OktaUserFactor
Remove-OktaUserSchemaProperty
Set-OktaConfig
Test-OktaAPI
Test-OktaUserTokenFactor
Update-OktaGroup
Update-OktaUserAttribute
