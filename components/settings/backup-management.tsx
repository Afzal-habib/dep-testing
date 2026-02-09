"use client"

import React, { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import Swal from 'sweetalert2'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Alert,
  AlertDescription,
} from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import CustomModal from '@/components/shared/custom-modal'
import { 
  Download, 
  Upload, 
  Database, 
  Plus,
  RefreshCcw,
  Loader2,
  CheckCircle,
  XCircle,
  AlertCircle,
  FolderOpen,
  FileText
} from 'lucide-react'
import { useBackup, BackupConfig, RestoreConfig, BackupInfo } from '@/hooks/use-backup'
import { useToast } from '@/hooks/use-toast'
import { backupFormSchema, restoreFormSchema } from '@/lib/validations/backup'



type BackupFormData = z.infer<typeof backupFormSchema>
type RestoreFormData = z.infer<typeof restoreFormSchema>

interface BackupManagementProps {
  className?: string
}

export function BackupManagement({ className }: BackupManagementProps) {
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [restoreDialogOpen, setRestoreDialogOpen] = useState(false)
  const [selectedBackup, setSelectedBackup] = useState<BackupInfo | null>(null)
  const { toast } = useToast()
  
  const {
    backups,
    serviceStatus,
    loading,
    error,
    backupInProgress,
    restoreInProgress,
    fetchBackups,
    createBackup,
    restoreBackup,
    isServiceAvailable,
    formatFileSize
  } = useBackup()

  // Initialize data on mount
  React.useEffect(() => {
    fetchBackups()
  }, [fetchBackups])

  // Backup form
  const backupForm = useForm<BackupFormData>({
    resolver: zodResolver(backupFormSchema),
    defaultValues: {
      destinationPath: './backups',
      backupName: '',
      description: '',
      compression: 'gzip',
      includeIndexes: true,
      generateTimestamp: true,
    }
  })

  // Restore form
  const restoreForm = useForm<RestoreFormData>({
    resolver: zodResolver(restoreFormSchema),
    defaultValues: {
      backupPath: '',
      targetDatabase: '',
      dropExisting: false,
      dryRun: false,
    }
  })

  // Handle backup creation
  const handleCreateBackup = async (data: BackupFormData) => {
    try {
      // Show confirmation dialog
      const result = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Create Database Backup?',
        html: `
          <div class="text-left">
            <p><strong>Destination:</strong> ${data.destinationPath}</p>
            ${data.backupName ? `<p><strong>Name:</strong> ${data.backupName}</p>` : ''}
            <p><strong>Compression:</strong> ${data.compression.toUpperCase()}</p>
            <p><strong>Include Indexes:</strong> ${data.includeIndexes ? 'Yes' : 'No'}</p>
            <p><strong>Add Timestamp:</strong> ${data.generateTimestamp ? 'Yes' : 'No'}</p>
            ${data.description ? `<p><strong>Description:</strong> ${data.description}</p>` : ''}
          </div>
        `,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Create Backup',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33'
      })

      if (!result.isConfirmed) return

      // Show loading
      Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Creating Backup...',
        text: 'Please wait while we create your database backup.',
        allowOutsideClick: false,
        didOpen: () => {
          Swal.showLoading()
        }
      })

      const config: BackupConfig = {
        destinationPath: data.destinationPath,
        backupName: data.backupName || undefined,
        description: data.description || undefined,
        compression: data.compression,
        includeIndexes: data.includeIndexes,
        generateTimestamp: data.generateTimestamp,
      }

      const success = await createBackup(config)
      
      if (success) {
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Backup Created Successfully!',
          text: `Database backup has been created at ${data.destinationPath}`,
          icon: 'success',
          confirmButtonText: 'OK'
        })
        
        setCreateDialogOpen(false)
        // Reset form with proper default values
        backupForm.reset({
          destinationPath: './backups',
          backupName: '',
          description: '',
          compression: 'gzip',
          includeIndexes: true,
          generateTimestamp: true,
        })
      } else {
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Backup Failed!',
          text: 'Failed to create database backup. Please try again.',
          icon: 'error',
          confirmButtonText: 'OK'
        })
      }
    } catch (error: any) {
      console.error('Backup creation error:', error)
      await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Error!',
        text: error.message || 'An unexpected error occurred while creating backup.',
        icon: 'error',
        confirmButtonText: 'OK'
      })
    }
  }

  // Handle backup creation with immediate download
  const handleCreateAndDownload = async (data: BackupFormData) => {
    try {
      // Show confirmation dialog
      const result = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Create & Download Backup?',
        html: `
          <div class="text-left">
            <p><strong>Compression:</strong> ${data.compression.toUpperCase()}</p>
            <p><strong>Include Indexes:</strong> ${data.includeIndexes ? 'Yes' : 'No'}</p>
            ${data.description ? `<p><strong>Description:</strong> ${data.description}</p>` : ''}
            <br>
            <p class="text-sm text-gray-600">The backup will be created and automatically downloaded to your device.</p>
          </div>
        `,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Create & Download',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33'
      })

      if (!result.isConfirmed) return

      // Pre-select save location if File System Access API is available
      let fileHandle = null
      const suggestedFileName = `backup_${new Date().toISOString().replace(/[:.]/g, '-')}.json`
      
      if ('showSaveFilePicker' in window) {
        const saveLocationResult = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Choose Save Location?',
          text: 'Do you want to choose where to save the backup file?',
          icon: 'question',
          showCancelButton: true,
          showDenyButton: true,
          confirmButtonText: 'Choose Location',
          denyButtonText: 'Use Downloads Folder',
          cancelButtonText: 'Cancel',
          confirmButtonColor: '#3085d6',
          denyButtonColor: '#28a745',
          cancelButtonColor: '#6c757d'
        })

        if (saveLocationResult.isDismissed) return
        
        if (saveLocationResult.isConfirmed) {
          fileHandle = await getFileHandleForSave(suggestedFileName)
          if (fileHandle === 'cancelled') return
        }
      }

      // Show loading
      Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Creating Backup...',
        text: 'Please wait while we create and prepare your backup for download.',
        allowOutsideClick: false,
        didOpen: () => {
          Swal.showLoading()
        }
      })

      const config = {
        destinationPath: data.destinationPath,
        backupName: data.backupName || undefined,
        description: data.description || undefined,
        compression: data.compression,
        includeIndexes: data.includeIndexes,
        generateTimestamp: data.generateTimestamp,
      }

      const response = await fetch('/api/settings/backup/create-download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`)
      }

      // Create blob from response
      const blob = await response.blob()
      const contentDisposition = response.headers.get('content-disposition')
      const fileName = contentDisposition?.match(/filename="(.+)"/)?.[1] || suggestedFileName
      
      // Save file using pre-selected handle or fallback method
      let saveResult
      if (fileHandle && fileHandle !== 'cancelled') {
        try {
          const writable = await fileHandle.createWritable()
          await writable.write(blob)
          await writable.close()
          saveResult = { success: true, fileName: fileHandle.name, method: 'file-system-access' }
        } catch (error: any) {
          console.error('File System Access API save failed:', error)
          saveResult = await saveFileToUserLocation(blob, fileName, false)
        }
      } else {
        saveResult = await saveFileToUserLocation(blob, fileName, false)
      }
      
      if (saveResult.success) {
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Backup Saved!',
          html: `
            <div class="text-left">
              <p><strong>File:</strong> ${saveResult.fileName}</p>
              <p><strong>Method:</strong> ${saveResult.method === 'file-system-access' ? 'Saved to selected location' : 'Downloaded to default location'}</p>
            </div>
          `,
          icon: 'success',
          confirmButtonText: 'OK'
        })
      } else {
        if (saveResult.error?.includes('cancelled')) {
          return
        }
        throw new Error('Failed to save file')
      }

      setCreateDialogOpen(false)
      backupForm.reset({
        destinationPath: './backups',
        backupName: '',
        description: '',
        compression: 'gzip',
        includeIndexes: true,
        generateTimestamp: true,
      })
    } catch (error: any) {
      console.error('Create and download error:', error)
      await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Download Failed!',
        text: error.message || 'An error occurred while creating and downloading the backup.',
        icon: 'error',
        confirmButtonText: 'OK'
      })
    }
  }

  // Handle backup restoration
  const handleRestoreBackup = async (data: RestoreFormData) => {
    try {
      // Check if we have selected file content or need to use server path
      const isFileSelected = selectedFileHandle && selectedFileContent
      
      if (!isFileSelected) {
        // Validate backup file extension for server paths
        if (!data.backupPath.toLowerCase().endsWith('.json')) {
          await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
            title: 'Invalid File Type!',
            text: 'Please select a valid JSON backup file.',
            icon: 'error',
            confirmButtonText: 'OK'
          })
          return
        }
      }

      // Show confirmation dialog with detailed info
      const warningText = data.dropExisting 
        ? '<p class="text-red-600 font-semibold">⚠️ WARNING: This will delete all existing data before restoring!</p>'
        : '<p class="text-blue-600">Existing data will be preserved and merged with backup data.</p>'

      const result = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: data.dryRun ? 'Validate Backup File?' : 'Restore Database Backup?',
        html: `
          <div class="text-left">
            <p><strong>Backup File:</strong> ${data.backupPath.split(/[\\/]/).pop() || data.backupPath}</p>
            ${data.targetDatabase ? `<p><strong>Target Database:</strong> ${data.targetDatabase}</p>` : ''}
            <p><strong>Source:</strong> ${isFileSelected ? 'Selected File' : 'Server File'}</p>
            <p><strong>Operation:</strong> ${data.dryRun ? 'Validation Only (Dry Run)' : 'Full Restore'}</p>
            ${!data.dryRun ? warningText : ''}
          </div>
        `,
        icon: data.dropExisting && !data.dryRun ? 'warning' : 'question',
        showCancelButton: true,
        confirmButtonText: data.dryRun ? 'Validate' : 'Restore',
        cancelButtonText: 'Cancel',
        confirmButtonColor: data.dropExisting && !data.dryRun ? '#dc3545' : '#3085d6',
        cancelButtonColor: '#6c757d'
      })

      if (!result.isConfirmed) return

      // Show loading
      Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: data.dryRun ? 'Validating Backup...' : 'Restoring Database...',
        text: data.dryRun ? 'Please wait while we validate your backup file.' : 'Please wait while we restore your database.',
        allowOutsideClick: false,
        didOpen: () => {
          Swal.showLoading()
        }
      })

      let success = false

      if (isFileSelected && selectedFileContent) {
        // Use client-side validation and API endpoint for file upload
        try {
          if (data.dryRun) {
            // Client-side validation for dry run
            const backupData = JSON.parse(selectedFileContent)
            if (!backupData.metadata || !backupData.collections) {
              throw new Error('Invalid backup file structure')
            }
            success = true
          } else {
            // Send file content to server for restore
            const response = await fetch('/api/settings/backup', {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                backupContent: selectedFileContent,
                targetDatabase: data.targetDatabase || undefined,
                dropExisting: data.dropExisting,
                dryRun: data.dryRun,
                isFileUpload: true
              })
            })

            const result = await response.json()
            success = response.ok && result.success
            
            if (!success) {
              throw new Error(result.error || 'Restore failed')
            }
          }
        } catch (error: any) {
          console.error('File restore error:', error)
          throw new Error(error.message || 'Failed to restore from selected file')
        }
      } else {
        // Use existing server-side restore functionality
        const config: RestoreConfig = {
          backupPath: data.backupPath,
          targetDatabase: data.targetDatabase || undefined,
          dropExisting: data.dropExisting,
          dryRun: data.dryRun,
        }

        success = await restoreBackup(config)
      }
      
      if (success) {
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: data.dryRun ? 'Validation Successful!' : 'Database Restored!',
          text: data.dryRun 
            ? 'The backup file is valid and can be restored.'
            : 'Database has been successfully restored from backup.',
          icon: 'success',
          confirmButtonText: 'OK'
        })
        
        setRestoreDialogOpen(false)
        // Reset form and selected file
        restoreForm.reset({
          backupPath: '',
          targetDatabase: '',
          dropExisting: false,
          dryRun: false,
        })
        setSelectedBackup(null)
        setSelectedFileHandle(null)
        setSelectedFileContent(null)
      } else {
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: data.dryRun ? 'Validation Failed!' : 'Restore Failed!',
          text: data.dryRun 
            ? 'The backup file is invalid or corrupted.'
            : 'Failed to restore database from backup. Please check the backup file.',
          icon: 'error',
          confirmButtonText: 'OK'
        })
      }
    } catch (error: any) {
      console.error('Backup restoration error:', error)
      await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Error!',
        text: error.message || 'An unexpected error occurred during restore operation.',
        icon: 'error',
        confirmButtonText: 'OK'
      })
    }
  }

  // Handle folder selection using File System Access API
  const handleFolderSelect = async () => {
    try {
      // Check if File System Access API is supported
      if ('showDirectoryPicker' in window) {
        const directoryHandle = await (window as any).showDirectoryPicker({
          mode: 'readwrite',
          startIn: 'downloads'
        })
        
        // Create a more descriptive path
        const folderPath = `./${directoryHandle.name}`
        backupForm.setValue('destinationPath', folderPath)
        
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Folder Selected!',
          text: `Backup destination set to: ${folderPath}`,
          icon: 'success',
          timer: 2000,
          showConfirmButton: false
        })
      } else {
        // Fallback for browsers that don't support File System Access API
        const result = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Select Backup Destination',
          html: `
            <div class="text-left">
              <p class="mb-3">Choose a backup destination:</p>
              <button id="relative-path" class="w-full p-2 mb-2 border rounded hover:bg-gray-50">./backups (Recommended)</button>
              <button id="desktop-path" class="w-full p-2 mb-2 border rounded hover:bg-gray-50">Desktop folder</button>
              <button id="documents-path" class="w-full p-2 mb-2 border rounded hover:bg-gray-50">Documents folder</button>
              <button id="custom-path" class="w-full p-2 border rounded hover:bg-gray-50">Enter custom path</button>
            </div>
          `,
          showConfirmButton: false,
          showCancelButton: true,
          cancelButtonText: 'Cancel',
          didOpen: () => {
            const relativePath = document.getElementById('relative-path')
            const desktopPath = document.getElementById('desktop-path')
            const documentsPath = document.getElementById('documents-path')
            const customPath = document.getElementById('custom-path')
            
            relativePath?.addEventListener('click', () => {
              backupForm.setValue('destinationPath', './backups')
              Swal.close()
            })
            
            desktopPath?.addEventListener('click', () => {
              const path = navigator.platform.indexOf('Win') !== -1
                ? `${process.env.USERPROFILE || 'C:\\Users\\User'}\\Desktop\\backups`
                : `${process.env.HOME || '/home/user'}/Desktop/backups`
              backupForm.setValue('destinationPath', path)
              Swal.close()
            })
            
            documentsPath?.addEventListener('click', () => {
              const path = navigator.platform.indexOf('Win') !== -1
                ? `${process.env.USERPROFILE || 'C:\\Users\\User'}\\Documents\\backups`
                : `${process.env.HOME || '/home/user'}/Documents/backups`
              backupForm.setValue('destinationPath', path)
              Swal.close()
            })
            
            customPath?.addEventListener('click', async () => {
              const { value } = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
                title: 'Enter Custom Path',
                input: 'text',
                inputPlaceholder: 'Enter full path to backup directory',
                inputValue: backupForm.getValues('destinationPath'),
                showCancelButton: true
              })
              
              if (value) {
                backupForm.setValue('destinationPath', value)
              }
              Swal.close()
            })
          }
        })
      }
    } catch (error) {
      // User cancelled the picker or error occurred
      console.log('Folder selection cancelled or failed:', error)
    }
  }

  // Store selected file handle for restore operations
  const [selectedFileHandle, setSelectedFileHandle] = useState<any>(null)
  const [selectedFileContent, setSelectedFileContent] = useState<string | null>(null)

  // Handle backup file selection for restore
  const handleFileSelect = async () => {
    try {
      // Check if File System Access API is supported
      if ('showOpenFilePicker' in window) {
        const [fileHandle] = await (window as any).showOpenFilePicker({
          types: [{
            description: 'JSON backup files',
            accept: {
              'application/json': ['.json'],
            },
          }],
          excludeAcceptAllOption: true,
          multiple: false,
        })
        
        // Store the file handle and read content for validation
        setSelectedFileHandle(fileHandle)
        
        try {
          const file = await fileHandle.getFile()
          const content = await file.text()
          
          // Validate JSON format
          JSON.parse(content)
          setSelectedFileContent(content)
          
          // Set form value to file name for display
          restoreForm.setValue('backupPath', fileHandle.name)
          
          await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
            title: 'File Selected!',
            html: `
              <div class="text-left">
                <p><strong>File:</strong> ${fileHandle.name}</p>
                <p><strong>Size:</strong> ${(content.length / 1024).toFixed(2)} KB</p>
                <p class="text-green-600">✓ Valid JSON format</p>
              </div>
            `,
            icon: 'success',
            timer: 3000,
            showConfirmButton: false
          })
        } catch (error) {
          await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
            title: 'Invalid Backup File!',
            text: 'The selected file is not a valid JSON backup file.',
            icon: 'error',
            confirmButtonText: 'OK'
          })
          setSelectedFileHandle(null)
          setSelectedFileContent(null)
        }
      } else {
        // Fallback: create file input element
        const input = document.createElement('input')
        input.type = 'file'
        input.accept = '.json'
        input.onchange = async (e) => {
          const file = (e.target as HTMLInputElement).files?.[0]
          if (file) {
            if (!file.name.toLowerCase().endsWith('.json')) {
              await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
                title: 'Invalid File Type!',
                text: 'Please select a JSON backup file.',
                icon: 'error',
                confirmButtonText: 'OK'
              })
              return
            }
            
            try {
              const content = await file.text()
              
              // Validate JSON format
              JSON.parse(content)
              setSelectedFileContent(content)
              
              // Store file reference
              setSelectedFileHandle({ name: file.name, isLegacy: true })
              
              // Set form value
              restoreForm.setValue('backupPath', file.name)
              
              await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
                title: 'File Selected!',
                html: `
                  <div class="text-left">
                    <p><strong>File:</strong> ${file.name}</p>
                    <p><strong>Size:</strong> ${(content.length / 1024).toFixed(2)} KB</p>
                    <p class="text-green-600">✓ Valid JSON format</p>
                  </div>
                `,
                icon: 'success',
                timer: 3000,
                showConfirmButton: false
              })
            } catch (error) {
              await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
                title: 'Invalid Backup File!',
                text: 'The selected file is not a valid JSON backup file.',
                icon: 'error',
                confirmButtonText: 'OK'
              })
              setSelectedFileHandle(null)
              setSelectedFileContent(null)
            }
          }
        }
        input.click()
      }
    } catch (error) {
      console.log('File selection cancelled or failed:', error)
    }
  }

  // Helper function to save file using File System Access API
  const saveFileToUserLocation = async (blob: Blob, defaultFileName: string, directUserGesture: boolean = false) => {
    try {
      // Check if File System Access API is supported and we have a direct user gesture
      if ('showSaveFilePicker' in window && directUserGesture) {
        const fileHandle = await (window as any).showSaveFilePicker({
          types: [{
            description: 'JSON backup files',
            accept: {
              'application/json': ['.json'],
            },
          }],
          suggestedName: defaultFileName,
          excludeAcceptAllOption: true,
        })
        
        const writable = await fileHandle.createWritable()
        await writable.write(blob)
        await writable.close()
        
        return { success: true, fileName: fileHandle.name, method: 'file-system-access' }
      } else {
        // Fallback: use traditional download method
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = defaultFileName
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        
        return { success: true, fileName: defaultFileName, method: 'traditional-download' }
      }
    } catch (error: any) {
      if (error.name === 'AbortError') {
        return { success: false, error: 'User cancelled file save' }
      }
      throw error
    }
  }

  // Get file handle with user gesture for save operations
  const getFileHandleForSave = async (defaultFileName: string) => {
    try {
      if ('showSaveFilePicker' in window) {
        return await (window as any).showSaveFilePicker({
          types: [{
            description: 'JSON backup files',
            accept: {
              'application/json': ['.json'],
            },
          }],
          suggestedName: defaultFileName,
          excludeAcceptAllOption: true,
        })
      }
      return null
    } catch (error: any) {
      if (error.name === 'AbortError') {
        return 'cancelled'
      }
      throw error
    }
  }

  // Handle backup download
  const handleDownloadBackup = async (backup: BackupInfo) => {
    try {
      // Show confirmation dialog
      const result = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Download Backup File?',
        html: `
          <div class="text-left">
            <p><strong>File:</strong> ${backup.name}</p>
            <p><strong>Size:</strong> ${backup.formattedSize}</p>
            <p><strong>Created:</strong> ${new Date(backup.createdAt).toLocaleString()}</p>
          </div>
        `,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Download',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#6c757d'
      })

      if (!result.isConfirmed) return

      // Pre-select save location if File System Access API is available
      let fileHandle = null
      
      if ('showSaveFilePicker' in window) {
        const saveLocationResult = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'Choose Save Location?',
          text: 'Do you want to choose where to save the backup file?',
          icon: 'question',
          showCancelButton: true,
          showDenyButton: true,
          confirmButtonText: 'Choose Location',
          denyButtonText: 'Use Downloads Folder',
          cancelButtonText: 'Cancel',
          confirmButtonColor: '#3085d6',
          denyButtonColor: '#28a745',
          cancelButtonColor: '#6c757d'
        })

        if (saveLocationResult.isDismissed) return
        
        if (saveLocationResult.isConfirmed) {
          fileHandle = await getFileHandleForSave(backup.name)
          if (fileHandle === 'cancelled') return
        }
      }

      // Show loading
      Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Downloading...',
        text: 'Please wait while we prepare your backup file.',
        allowOutsideClick: false,
        didOpen: () => {
          Swal.showLoading()
        }
      })

      const response = await fetch(`/api/settings/backup/download?path=${encodeURIComponent(backup.path)}`)
      
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Failed to download backup file')
      }

      // Create blob from response
      const blob = await response.blob()
      
      // Save file using pre-selected handle or fallback method
      let saveResult
      if (fileHandle && fileHandle !== 'cancelled') {
        try {
          const writable = await fileHandle.createWritable()
          await writable.write(blob)
          await writable.close()
          saveResult = { success: true, fileName: fileHandle.name, method: 'file-system-access' }
        } catch (error: any) {
          console.error('File System Access API save failed:', error)
          saveResult = await saveFileToUserLocation(blob, backup.name, false)
        }
      } else {
        saveResult = await saveFileToUserLocation(blob, backup.name, false)
      }
      
      if (saveResult.success) {
        await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
          title: 'File Saved!',
          html: `
            <div class="text-left">
              <p><strong>File:</strong> ${saveResult.fileName}</p>
              <p><strong>Size:</strong> ${backup.formattedSize}</p>
              <p><strong>Method:</strong> ${saveResult.method === 'file-system-access' ? 'Saved to selected location' : 'Downloaded to default location'}</p>
            </div>
          `,
          icon: 'success',
          confirmButtonText: 'OK'
        })
      } else {
        if (saveResult.error?.includes('cancelled')) {
          return
        }
        throw new Error('Failed to save file')
      }
    } catch (error: any) {
      console.error('Download error:', error)
      await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Download Failed!',
        text: error.message || 'An error occurred while downloading the backup file.',
        icon: 'error',
        confirmButtonText: 'OK'
      })
    }
  }

  // Handle backup selection for restore
  const handleBackupSelect = async (backup: BackupInfo) => {
    try {
      // Show confirmation dialog
      const result = await Swal.fire({
       customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
        title: 'Restore from this Backup?',
        html: `
          <div class="text-left">
            <p><strong>File:</strong> ${backup.name}</p>
            <p><strong>Size:</strong> ${backup.formattedSize}</p>
            <p><strong>Created:</strong> ${new Date(backup.createdAt).toLocaleString()}</p>
            <br>
            <p class="text-sm text-gray-600">This will open the restore dialog where you can configure restore options.</p>
          </div>
        `,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Select for Restore',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#6c757d'
      })

      if (!result.isConfirmed) return

      setSelectedBackup(backup)
      // Clear any selected file from file picker
      setSelectedFileHandle(null)
      setSelectedFileContent(null)
      // Reset form with new values to prevent uncontrolled to controlled warning
      restoreForm.reset({
        backupPath: backup.path,
        targetDatabase: '',
        dropExisting: false,
        dryRun: false,
      })
      setRestoreDialogOpen(true)
    } catch (error) {
      console.error('Backup selection error:', error)
    }
  }

  const renderServiceStatus = () => {
    if (!serviceStatus) return null

    const { available, error, databaseInfo } = serviceStatus

    return (
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            {available ? (
              <CheckCircle className="w-5 h-5 text-green-600" />
            ) : (
              <XCircle className="w-5 h-5 text-red-600" />
            )}
            <span>Backup Service Status</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {available ? (
            <div>
              {databaseInfo && (
                <div className="text-sm text-muted-foreground">
                  <p>Database: {databaseInfo.database}</p>
                  <p>Collections: {databaseInfo.collections}</p>
                  <p>Total Documents: {databaseInfo.totalDocuments?.toLocaleString()}</p>
                </div>
              )}
            </div>
          ) : (
            <Alert variant="destructive">
              <AlertCircle className="w-4 h-4" />
              <AlertDescription>
                {error || 'Backup service is not available. Please check your database connection.'}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    )
  }

  const renderBackupList = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center p-8">
          <Loader2 className="w-6 h-6 animate-spin mr-2" />
          <span>Loading backups...</span>
        </div>
      )
    }

    if (backups.length === 0) {
      return (
        <div className="text-center p-8 text-muted-foreground">
          <Database className="w-12 h-12 mx-auto mb-4 opacity-50" />
          <p>No backups found</p>
          <p className="text-sm">Create your first backup to get started</p>
        </div>
      )
    }

    return (
      <div className="space-y-2">
        {backups.map((backup, index) => (
          <div
            key={index}
            className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
          >
            <div className="flex-1">
              <div className="flex items-center space-x-2">
                <span className="font-medium">{backup.name}</span>
                {backup.isDirectory ? (
                  <Badge variant="secondary">Directory</Badge>
                ) : (
                  <Badge variant="outline">File</Badge>
                )}
              </div>
              <div className="text-sm text-muted-foreground mt-1">
                <span>Size: {backup.formattedSize}</span>
                <span className="mx-2">•</span>
                <span>Created: {new Date(backup.createdAt).toLocaleString()}</span>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleDownloadBackup(backup)}
                disabled={loading}
              >
                <Download className="w-4 h-4 mr-1" />
                Download
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleBackupSelect(backup)}
                disabled={!isServiceAvailable() || restoreInProgress}
              >
                <Upload className="w-4 h-4 mr-1" />
                Restore
              </Button>
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className={className}>
        <Alert variant="destructive">
          <AlertCircle className="w-4 h-4" />
          <AlertDescription>
            {error}
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  return (
    <div className={className}>
      {renderServiceStatus()}

      <div className="grid gap-6 md:grid-cols-2">
        {/* Create Backup */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Download className="w-5 h-5" />
              <span>Create Backup</span>
            </CardTitle>
            <CardDescription>
              Create a backup of your MongoDB database
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button 
              className="w-full" 
              disabled={!isServiceAvailable() || backupInProgress}
              onClick={() => setCreateDialogOpen(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              Create Backup
            </Button>
          </CardContent>
        </Card>

        {/* Restore Backup */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Upload className="w-5 h-5" />
              <span>Restore Backup</span>
            </CardTitle>
            <CardDescription>
              Restore database from a backup file
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button 
              className="w-full" 
              variant="outline"
              disabled={!isServiceAvailable() || restoreInProgress}
              onClick={() => setRestoreDialogOpen(true)}
            >
              <Upload className="w-4 h-4 mr-2" />
              Restore from File
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Backup History */}
      <Card className="mt-6">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Database className="w-5 h-5" />
                <span>Backup History</span>
              </CardTitle>
              <CardDescription>
                Previously created backups available for restore
              </CardDescription>
            </div>
            <Button 
              variant="outline" 
              size="sm"
              onClick={fetchBackups}
              disabled={loading}
            >
              <RefreshCcw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {renderBackupList()}
        </CardContent>
      </Card>

      {/* Create Backup Modal */}
      <CustomModal
        isOpen={createDialogOpen}
        onClose={() => {
          setCreateDialogOpen(false)
          // Reset form when modal closes
          backupForm.reset({
            destinationPath: './backups',
            backupName: '',
            description: '',
            compression: 'gzip',
            includeIndexes: true,
            generateTimestamp: true,
          })
        }}
        title="Create Database Backup"
        modalSize="md"
      >
        <div className="text-sm text-muted-foreground mb-4">
          Configure backup settings and choose destination
        </div>
        <Form {...backupForm}>
          <form onSubmit={backupForm.handleSubmit(handleCreateBackup)} className="space-y-4">
            <FormField
              control={backupForm.control}
              name="destinationPath"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Destination Path</FormLabel>
                  <FormControl>
                    <div className="flex space-x-2">
                      <Input {...field} placeholder="./backups" />
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={handleFolderSelect}
                        title="Select folder (modern browsers) or use default location"
                      >
                        <FolderOpen className="w-4 h-4" />
                      </Button>
                    </div>
                  </FormControl>
                  <FormDescription>
                    Server directory path for backup storage. For downloads, you'll choose the save location separately.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={backupForm.control}
              name="backupName"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Backup Name (Optional)</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="Custom name for backup (timestamp will be added)" />
                  </FormControl>
                  <FormDescription>
                    Custom name for backup (timestamp will be added)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={backupForm.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description (Optional)</FormLabel>
                  <FormControl>
                    <Textarea 
                      {...field} 
                      placeholder="Description of this backup"
                      rows={2}
                    />
                  </FormControl>
                  <FormDescription>
                    Optional description for this backup
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={backupForm.control}
              name="compression"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Compression</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select compression" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="gzip">GZIP</SelectItem>
                      <SelectItem value="none">None</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Compression format for the backup file
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={backupForm.control}
              name="includeIndexes"
              render={({ field }) => (
                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                  <div className="space-y-0.5">
                    <FormLabel>Include Indexes</FormLabel>
                    <FormDescription>
                      Include database indexes in backup
                    </FormDescription>
                  </div>
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <FormField
              control={backupForm.control}
              name="generateTimestamp"
              render={({ field }) => (
                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                  <div className="space-y-0.5">
                    <FormLabel>Add Timestamp</FormLabel>
                    <FormDescription>
                      Add timestamp to backup filename
                    </FormDescription>
                  </div>
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <div className="flex justify-end space-x-3 pt-4">
              <Button 
                type="submit" 
                variant="outline"
                disabled={backupInProgress}
              >
                {backupInProgress ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Database className="w-4 h-4 mr-2" />
                )}
                Create & Save
              </Button>
              <Button 
                type="button"
                onClick={backupForm.handleSubmit(handleCreateAndDownload)}
                disabled={backupInProgress}
              >
                {backupInProgress ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Download className="w-4 h-4 mr-2" />
                )}
                Create & Download
              </Button>
            </div>
          </form>
        </Form>
      </CustomModal>

      {/* Restore Backup Modal */}
      <CustomModal
        isOpen={restoreDialogOpen}
        onClose={() => {
          setRestoreDialogOpen(false)
          // Reset form when modal closes
          restoreForm.reset({
            backupPath: '',
            targetDatabase: '',
            dropExisting: false,
            dryRun: false,
          })
          setSelectedBackup(null)
        }}
        title="Restore Database Backup"
        modalSize="md"
      >
        <div className="text-sm text-muted-foreground mb-4">
          Restore your database from a backup file
        </div>
        <Form {...restoreForm}>
          <form onSubmit={restoreForm.handleSubmit(handleRestoreBackup)} className="space-y-4">
            <FormField
              control={restoreForm.control}
              name="backupPath"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Backup File Path</FormLabel>
                  <FormControl>
                    <div className="flex space-x-2">
                      <Input {...field} placeholder="Select or enter path to JSON backup file" />
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={handleFileSelect}
                        title="Select backup file (.json)"
                      >
                        <FileText className="w-4 h-4" />
                      </Button>
                    </div>
                  </FormControl>
                  <FormDescription>
                    Select a JSON backup file or enter the full path to the backup file
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={restoreForm.control}
              name="targetDatabase"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Target Database (Optional)</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="Leave empty to restore to original database" />
                  </FormControl>
                  <FormDescription>
                    Specify different database name to restore to
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={restoreForm.control}
              name="dropExisting"
              render={({ field }) => (
                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                  <div className="space-y-0.5">
                    <FormLabel>Drop Existing Data</FormLabel>
                    <FormDescription>
                      Remove existing data before restoring
                    </FormDescription>
                  </div>
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <FormField
              control={restoreForm.control}
              name="dryRun"
              render={({ field }) => (
                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                  <div className="space-y-0.5">
                    <FormLabel>Dry Run</FormLabel>
                    <FormDescription>
                      Validate backup without applying changes
                    </FormDescription>
                  </div>
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <div className="flex justify-end pt-4">
              <Button 
                type="submit" 
                disabled={restoreInProgress}
              >
                {restoreInProgress ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Upload className="w-4 h-4 mr-2" />
                )}
                Restore Backup
              </Button>
            </div>
          </form>
        </Form>
      </CustomModal>
    </div>
  )
}