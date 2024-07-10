#!/bin/bash


# Array of GitHub repository URLs
REPOS=(
    "https://github.com/dirkjanm/ROADtools"
    "https://github.com/dafthack/PowerMeta"
    "https://github.com/NetSPI/MicroBurst"
    "https://github.com/nccgroup/ScoutSuite"
    "https://github.com/hausec/PowerZure"
    "https://github.com/fox-it/adconnectdump"
    "https://github.com/FSecureLABS/Azurite"
    "https://github.com/mburrough/pentestingazureapps"
    "https://github.com/Azure/Stormspotter"
    "https://github.com/nccgroup/azucar"
    "https://github.com/dafthack/MSOLSpray"
    "https://github.com/BloodHoundAD/BloodHound"
    "https://github.com/nccgroup/Carnivore"
    "https://github.com/CrowdStrike/CRT"
    "https://github.com/Kyuu-Ji/Awesome-Azure-Pentest"
    "https://github.com/cyberark/blobhunter"
    "https://github.com/Gerenios/AADInternals"
    "https://github.com/prowler-cloud/prowler"
    "https://github.com/Raikia/UhOh365"
)
# Clone each repository
for REPO in "${REPOS[@]}"; do
    git clone "$REPO"
done

echo "All repositories have been cloned."
