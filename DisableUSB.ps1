# --- USB Security Hardening and Validation Script for Issuing CA VM ---

# --- Helper Function for Validation ---
function Test-RegistryValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][int]$DesiredValue,
        [Parameter(Mandatory=$true)][string]$Description
    )
    $Status = "❌ INSECURE"
    $CurrentValue = "N/A (Key Missing)"
    
    if (Test-Path $Path) {
        $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($CurrentValue -eq $DesiredValue) {
            $Status = "✅ SECURE"
        }
    }
    
    Write-Host "    $Description"
    Write-Host "    Path: $Path"
    Write-Host "    Current Value: $CurrentValue"
    Write-Host "    Desired Value: $DesiredValue (for $Status)"
    
    # Track results for summary
    return $Status -eq "✅ SECURE"
}

# --- Step 1: Initial Validation (Check Current Status) ---
Write-Host "========================================================================="
Write-Host "--- STEP 1: INITIAL VALIDATION OF CURRENT USB SECURITY SETTINGS ---"
Write-Host "========================================================================="

$InitialSecureCount = 0

if (Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name 'Start' -DesiredValue 4 -Description '[1] USBSTOR Driver Status (Blocks local USB storage recognition)') {
    $InitialSecureCount++
}

if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCcm' -DesiredValue 1 -Description '[2] RDP Redirection Policy (Blocks USB redirection)') {
    $InitialSecureCount++
}

if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_All' -DesiredValue 1 -Description '[3] Removable Storage Policy (Denies all removable media access)') {
    $InitialSecureCount++
}

Write-Host "`n-- Initial Summary --"
Write-Host "$InitialSecureCount / 3 settings were already in the secure state."
Write-Host "---------------------"

# --- Step 2: Configure and Disable USB Policies Completely ---
Write-Host "`n========================================================================="
Write-Host "--- STEP 2: APPLYING SECURE CONFIGURATION (DISABLING USB ACCESS) ---"
Write-Host "========================================================================="

# 1. Disable USB Mass Storage Driver (USBSTOR)
$USBSTORPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR'
$DisabledValue = 4
Write-Host "Configuring USBSTOR..."
if (-not (Test-Path $USBSTORPath)) { New-Item -Path $USBSTORPath -Force | Out-Null }
Set-ItemProperty -Path $USBSTORPath -Name 'Start' -Value $DisabledValue -Type DWord -Force
Write-Host "  ✅ USBSTOR Start set to $DisabledValue (DISABLED)."

# 2. Block RDP Plug and Play Device Redirection
$RDPPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$BlockedValue = 1
Write-Host "Configuring RDP Redirection Policy..."
if (-not (Test-Path $RDPPath)) { New-Item -Path $RDPPath -Force | Out-Null }
Set-ItemProperty -Path $RDPPath -Name 'fDisableCcm' -Value $BlockedValue -Type DWord -Force
Write-Host "  ✅ fDisableCcm set to $BlockedValue (BLOCKED RDP redirection)."

# 3. Enforce Deny All Removable Storage Access (Local Policy)
$RemovablePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
$DenyValue = 1
Write-Host "Configuring Removable Storage Policy..."
if (-not (Test-Path $RemovablePath)) { New-Item -Path $RemovablePath -Force | Out-Null }
Set-ItemProperty -Path $RemovablePath -Name 'Deny_All' -Value $DenyValue -Type DWord -Force
Write-Host "  ✅ Deny_All set to $DenyValue (DENIED all removable storage access)."

# Force update of Group Policy to apply new settings immediately
Write-Host "`n--- Forcing Group Policy Update ---"
gpupdate /force
Write-Host "Policy update complete. Checking applied settings..."


# --- Step 3: Final Validation (Check Applied Status) ---
Write-Host "`n========================================================================="
Write-Host "--- STEP 3: FINAL VALIDATION OF APPLIED USB SECURITY SETTINGS ---"
Write-Host "========================================================================="

$FinalSecureCount = 0

if (Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name 'Start' -DesiredValue 4 -Description '[1] USBSTOR Driver Status') {
    $FinalSecureCount++
}

if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCcm' -DesiredValue 1 -Description '[2] RDP Redirection Policy') {
    $FinalSecureCount++
}

if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_All' -DesiredValue 1 -Description '[3] Removable Storage Policy') {
    $FinalSecureCount++
}

Write-Host "`n--- Final Summary ---"
if ($FinalSecureCount -eq 3) {
    Write-Host "🎉 **ALL 3 USB SECURITY SETTINGS ARE CORRECTLY CONFIGURED (3/3).**"
    Write-Host "The CA VM is now securely configured against USB threats."
} else {
    Write-Host "❌ **$FinalSecureCount/3 settings are secure.** Review the output above for any failures."
}
Write-Host "---------------------"
Write-Host "⚠️ **ACTION REQUIRED:** A **REBOOT** of the CA VM is strongly recommended for these changes to take full effect."

# Optional: Add a pause to allow the user to read the output
Read-Host "Press Enter to exit the script."