# Self-Hosted APT Repository Setup for ftr

This guide explains how to set up a self-hosted APT repository to distribute ftr packages to Ubuntu/Debian users.

## Prerequisites

- A web server (Apache, Nginx, or similar)
- `reprepro` tool for managing the repository
- GPG key for signing packages

## Step 1: Install Required Tools

```bash
sudo apt-get update
sudo apt-get install reprepro gnupg apache2
```

## Step 2: Create Repository Structure

```bash
# Create directory structure
sudo mkdir -p /var/www/apt/{conf,db,dists,pool}
cd /var/www/apt

# Create distributions file
sudo tee conf/distributions << EOF
Origin: David Weekly
Label: ftr
Codename: stable
Architectures: amd64 arm64
Components: main
Description: Fast TraceRoute APT Repository
SignWith: YOUR_GPG_KEY_ID
EOF
```

## Step 3: Generate GPG Key (if needed)

```bash
# Generate a new GPG key
gpg --gen-key

# Export public key
gpg --armor --export YOUR_EMAIL > /var/www/apt/ftr.gpg.key
```

## Step 4: Add Packages to Repository

```bash
# Add a .deb package
reprepro -b /var/www/apt includedeb stable ftr_*.deb

# List packages in repository
reprepro -b /var/www/apt list stable
```

## Step 5: Configure Web Server

### For Apache:

```apache
<VirtualHost *:80>
    ServerName apt.yourdomain.com
    DocumentRoot /var/www/apt
    
    <Directory /var/www/apt>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    # Enable directory listings
    <Directory /var/www/apt/pool>
        Options +Indexes
    </Directory>
</VirtualHost>
```

### For Nginx:

```nginx
server {
    listen 80;
    server_name apt.yourdomain.com;
    root /var/www/apt;
    
    location / {
        autoindex on;
    }
}
```

## Step 6: Client Configuration

Users can add your repository with:

```bash
# Add GPG key
wget -qO - https://apt.yourdomain.com/ftr.gpg.key | sudo apt-key add -

# Add repository
echo "deb https://apt.yourdomain.com stable main" | sudo tee /etc/apt/sources.list.d/ftr.list

# Update and install
sudo apt-get update
sudo apt-get install ftr
```

## Step 7: Automation

Create a script to automatically add new releases:

```bash
#!/bin/bash
# add-release.sh

REPO_DIR="/var/www/apt"
DEB_FILE="$1"

if [ -z "$DEB_FILE" ]; then
    echo "Usage: $0 <deb-file>"
    exit 1
fi

# Add to repository
reprepro -b "$REPO_DIR" includedeb stable "$DEB_FILE"

# Update repository metadata
reprepro -b "$REPO_DIR" export

echo "Package added successfully!"
```

## Step 8: GitHub Actions Integration

Add this job to your release workflow to automatically upload to your APT repository:

```yaml
upload-to-apt:
  name: Upload to APT Repository
  needs: build-deb
  runs-on: ubuntu-latest
  steps:
    - name: Download .deb artifacts
      uses: actions/download-artifact@v4
      with:
        pattern: ftr-deb-*
        merge-multiple: true
    
    - name: Upload to APT repository
      env:
        APT_SERVER: ${{ secrets.APT_SERVER }}
        APT_USER: ${{ secrets.APT_USER }}
        APT_KEY: ${{ secrets.APT_KEY }}
      run: |
        # Install SSH key
        mkdir -p ~/.ssh
        echo "$APT_KEY" > ~/.ssh/id_rsa
        chmod 600 ~/.ssh/id_rsa
        
        # Upload packages
        for deb in *.deb; do
          scp -o StrictHostKeyChecking=no "$deb" "$APT_USER@$APT_SERVER:/tmp/"
          ssh -o StrictHostKeyChecking=no "$APT_USER@$APT_SERVER" \
            "sudo /usr/local/bin/add-release.sh /tmp/$deb && rm /tmp/$deb"
        done
```

## Security Considerations

1. **Always sign packages** - Use GPG signing to ensure package integrity
2. **Use HTTPS** - Configure SSL/TLS for your APT repository
3. **Restrict upload access** - Only allow authorized users to add packages
4. **Regular updates** - Keep repository metadata and packages up to date

## Maintenance

```bash
# Check repository consistency
reprepro -b /var/www/apt check

# Remove old versions (keep last 3)
reprepro -b /var/www/apt listfilter stable 'Package (== ftr)' | tail -n +4 | while read pkg; do
    reprepro -b /var/www/apt remove stable ftr
done

# Clean up unreferenced files
reprepro -b /var/www/apt deleteunreferenced
```