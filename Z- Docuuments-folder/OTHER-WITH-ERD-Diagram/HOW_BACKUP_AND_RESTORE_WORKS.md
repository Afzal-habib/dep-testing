

## 🗄️ **Backup System Overview**

### **Architecture**
- **Native MongoDB Backup**: Uses MongoDB JavaScript client (no external tools like `mongodump`)
- **JSON Format**: Stores backups as structured JSON files
- **File System Access API**: Modern browser file handling with fallbacks
- **SweetAlert2**: Professional confirmation dialogs and notifications

### **How Backup Works**

1. **User Interface**:
   - Fill out backup form with destination path, name, description
   - Choose compression (gzip/none), include indexes, generate timestamp
   - Click "Create Backup" or "Create & Download"

2. **File Selection**:
   - Uses modern File System Access API for folder selection
   - Fallback to traditional file input for older browsers
   - Pre-selects download location to avoid user gesture issues

3. **Backend Process** (`NativeBackupService.createBackup`):
   ```
   ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
   │ Connect to DB   │ -> │ List Collections │ -> │ Export Each     │
   │                 │    │                  │    │ Collection      │
   └─────────────────┘    └──────────────────┘    └─────────────────┘
           │                        │                       │
           v                        v                       v
   ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
   │ Generate        │ -> │ Filter by        │ -> │ Create JSON     │
   │ Metadata        │    │ Include/Exclude  │    │ Structure       │
   └─────────────────┘    └──────────────────┘    └─────────────────┘
   ```

4. **JSON Structure**:
   ```json
   {
     "metadata": {
       "database": "crm_database",
       "timestamp": "2025-10-09T...",
       "backupName": "daily-backup",
       "description": "Daily CRM backup",
       "version": "1.0",
       "collections": ["users", "departments", "roles"],
       "compression": "none"
     },
     "collections": {
       "users": [{ /* user documents */ }],
       "departments": [{ /* department documents */ }],
       "roles": [{ /* role documents */ }]
     }
   }
   ```

5. **File Operations**:
   - Server saves to specified path: `e:\backups\crm-backup_2025-10-09.json`
   - Browser download triggers automatically
   - File size and document count reported

---

## 🔄 **Restore System Overview**

### **How Restore Works**

1. **Two Restore Methods**:
   
   **Method A: Server File Restore**
   - Select existing backup file from server
   - Specify file path on server filesystem
   - Good for scheduled/automated restores
   
   **Method B: Upload File Restore** 
   - Upload backup JSON file from user's computer
   - Validates JSON structure before processing
   - Good for manual/external backup files

2. **User Interface Flow**:
   ```
   Select Restore Method -> Choose/Upload File -> Configure Options -> Confirm -> Execute
   ```

3. **Configuration Options**:
   - **Target Database**: Restore to different database (optional)
   - **Drop Existing**: Clear collections before restore
   - **Dry Run**: Validate without making changes
   - **Restore Tables**: Select specific collections to restore

4. **Backend Process** (`NativeBackupService.restoreBackup`):
   ```
   ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
   │ Read/Parse      │ -> │ Validate JSON    │ -> │ Connect to DB   │
   │ Backup File     │    │ Structure        │    │                 │
   └─────────────────┘    └──────────────────┘    └─────────────────┘
           │                        │                       │
           v                        v                       v
   ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
   │ Drop Collections│ -> │ Import Each      │ -> │ Report Results  │
   │ (if enabled)    │    │ Collection       │    │                 │
   └─────────────────┘    └──────────────────┘    └─────────────────┘
   ```

5. **Safety Features**:
   - **Dry Run Mode**: Preview what will be restored without changes
   - **Validation**: Checks backup file structure and database connectivity
   - **Error Handling**: Detailed error messages and rollback on failure
   - **Audit Logging**: Tracks all backup/restore operations

---

## 🛡️ **Security & Validation**

### **Input Validation**:
- **Zod Schemas**: Type-safe validation for all inputs
- **Path Sanitization**: Prevents directory traversal attacks
- **XSS/SQL Injection**: Security middleware checks all string inputs
- **File Type Validation**: Only JSON files accepted for restore

### **API Endpoints** (`/api/settings/backup`):
- **GET**: List available backups with metadata
- **POST**: Create new backup with configuration
- **PUT**: Restore backup (both server file and upload methods)

### **Error Handling**:
```typescript
// Example error responses
{
  success: false,
  error: "Backup file does not exist",
  details: { /* additional context */ }
}
```

---

## 🎯 **Key Features**

1. **No External Dependencies**: Pure JavaScript/TypeScript implementation
2. **Cross-Browser Support**: File System Access API with fallbacks
3. **Professional UI**: SweetAlert2 confirmations and progress indicators
4. **Flexible Configuration**: Include/exclude collections, compression options
5. **Database Statistics**: Real-time info about database size and collections
6. **Audit Trail**: Detailed logging of all operations
7. **Multiple Restore Sources**: Server files or user uploads
8. **Safety First**: Dry run mode and validation before execution

The system is designed to be robust, user-friendly, and secure while providing both manual and programmatic backup/restore capabilities for your CRM database.