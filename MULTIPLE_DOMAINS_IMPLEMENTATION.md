# Multiple Domains Implementation

## Overview

This implementation adds comprehensive support for managing multiple domains in Evilginx3, allowing users to configure and use multiple domains simultaneously for phishing campaigns.

## Features

### 1. Multiple Domain Configuration
- Add multiple domains to the configuration
- Set a primary domain
- Enable/disable individual domains
- Remove domains (with safety checks)
- Automatic migration from legacy single-domain configuration

### 2. Domain Management Commands

#### List All Domains
```bash
config domains
```
Displays all configured domains with their status (enabled/disabled) and primary designation.

#### Add Domain
```bash
config domains add <domain> [description]
```
Adds a new domain to the configuration. Optional description can be provided.

Example:
```bash
config domains add example.com "Primary domain"
config domains add backup-domain.com "Backup domain"
```

#### Remove Domain
```bash
config domains remove <domain>
```
Removes a domain from the configuration. Cannot remove the last remaining domain.

#### Set Primary Domain
```bash
config domains set-primary <domain>
```
Sets the specified domain as the primary domain.

#### Enable/Disable Domain
```bash
config domains enable <domain>
config domains disable <domain>
```
Enables or disables a domain. Disabled domains won't be used for phishlet hostname validation.

### 3. Backward Compatibility

The implementation maintains full backward compatibility:
- Legacy `config domain <domain>` command still works
- Existing single-domain configurations are automatically migrated
- All existing phishlets continue to work without modification

## Technical Implementation

### Configuration Structure

```go
type DomainInfo struct {
    Domain      string `json:"domain" yaml:"domain"`
    IsPrimary   bool   `json:"is_primary" yaml:"is_primary"`
    Enabled     bool   `json:"enabled" yaml:"enabled"`
    AddedAt     string `json:"added_at,omitempty" yaml:"added_at,omitempty"`
    Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type GeneralConfig struct {
    Domain        string       // Legacy: kept for backward compatibility
    Domains       []DomainInfo // New: multiple domains support
    PrimaryDomain string       // Current primary domain
    // ... other fields
}
```

### Key Functions

#### `AddDomain(domain string, description string) error`
Adds a new domain to the configuration. Automatically makes it primary if it's the first domain.

#### `RemoveDomain(domain string) error`
Removes a domain. Automatically reassigns primary if the removed domain was primary.

#### `SetPrimaryDomain(domain string) error`
Sets a domain as primary. Updates legacy domain field for compatibility.

#### `EnableDomain(domain string, enabled bool) error`
Enables or disables a domain.

#### `IsDomainValid(domain string) bool`
Checks if a domain or hostname is valid against all enabled domains.

#### `GetPrimaryDomain() string`
Returns the primary domain, with fallback to legacy domain.

### Phishlet Hostname Validation

Updated `SetSiteHostname()` to validate hostnames against all enabled domains:

```go
// Validates hostname against all enabled domains
for _, d := range c.general.Domains {
    if d.Enabled {
        if hostname == d.Domain || strings.HasSuffix(hostname, "."+d.Domain) {
            valid = true
            break
        }
    }
}
```

### Migration Logic

Automatic migration from legacy single-domain to multi-domain:

```go
// Migrate legacy single domain to multi-domain structure
if len(c.general.Domains) == 0 && c.general.Domain != "" {
    c.general.Domains = []DomainInfo{
        {
            Domain:    c.general.Domain,
            IsPrimary: true,
            Enabled:   true,
            AddedAt:   time.Now().Format(time.RFC3339),
        },
    }
    c.general.PrimaryDomain = c.general.Domain
    // ... save configuration
}
```

## Usage Examples

### Basic Setup

```bash
# Add first domain (automatically becomes primary)
config domains add example.com "Main domain"

# Add additional domains
config domains add backup1.com "Backup domain 1"
config domains add backup2.com "Backup domain 2"

# List all domains
config domains

# Set a different primary domain
config domains set-primary backup1.com

# Disable a domain temporarily
config domains disable backup2.com

# Re-enable it
config domains enable backup2.com
```

### Phishlet Configuration

Phishlets can now use any of the configured domains:

```bash
# Configure phishlet with primary domain
phishlets hostname o365 login.example.com

# Or use a different configured domain
phishlets hostname o365 login.backup1.com

# Both will work as long as the domains are enabled
```

### Viewing Configuration

```bash
# View all configuration (shows primary domain and domain count)
config

# View only domains
config domains
```

## Configuration File Structure

The configuration is stored in `~/.evilginx/config.json`:

```json
{
  "general": {
    "domain": "example.com",
    "primary_domain": "example.com",
    "domains": [
      {
        "domain": "example.com",
        "is_primary": true,
        "enabled": true,
        "added_at": "2024-01-01T00:00:00Z",
        "description": "Main domain"
      },
      {
        "domain": "backup1.com",
        "is_primary": false,
        "enabled": true,
        "added_at": "2024-01-02T00:00:00Z",
        "description": "Backup domain 1"
      }
    ]
  }
}
```

## Benefits

1. **Flexibility**: Use multiple domains for different campaigns or purposes
2. **Redundancy**: Have backup domains ready if primary domain is compromised
3. **Organization**: Add descriptions to track domain purposes
4. **Control**: Enable/disable domains without removing them
5. **Compatibility**: Full backward compatibility with existing configurations

## Safety Features

- Cannot remove the last remaining domain
- Automatic primary domain reassignment if primary is removed
- Validation ensures hostnames match configured domains
- Disabled domains are excluded from validation

## Future Enhancements

Potential future improvements:
- Domain health checking
- Automatic domain rotation
- Domain usage statistics
- Per-domain certificate management
- Domain-specific configurations

## Testing

To test the implementation:

1. Start Evilginx
2. Add multiple domains: `config domains add domain1.com`
3. List domains: `config domains`
4. Configure a phishlet with one domain
5. Switch primary domain and verify it still works
6. Test disabling/enabling domains

## Notes

- The legacy `config domain` command still works and sets the primary domain
- All existing phishlets will continue to work without modification
- Domain validation is performed against all enabled domains
- The primary domain is used as fallback in various places for backward compatibility




