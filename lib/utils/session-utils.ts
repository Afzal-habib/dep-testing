/**
 * Utility functions for managing session cleanup
 * Updated for server-side session management with NextAuth
 */

export const SessionUtils = {
  /**
   * @deprecated Clear auth data from browser storage - NextAuth handles this automatically
   */
  clearAllAuthData(): void {
    console.warn('clearAllAuthData is deprecated. NextAuth handles session cleanup automatically.')
    
    if (typeof window === 'undefined') return

    try {
      // Only clear legacy data that might remain from old system
      const legacyKeys = [
        'logged_in_user', 'user_permissions', 'user_role', 'user_department'
      ]
      
      legacyKeys.forEach(key => {
        if (localStorage.getItem(key)) {
          localStorage.removeItem(key)
          console.log(`Cleaned up legacy key: ${key}`)
        }
      })

      console.log('✅ Legacy authentication data cleanup completed')
    } catch (error) {
      console.error('❌ Error during legacy cleanup:', error)
    }
  },

  /**
   * @deprecated Validate session - NextAuth handles session validation automatically
   */
  validateAndCleanSession(): boolean {
    console.warn('validateAndCleanSession is deprecated. NextAuth handles session validation automatically.')
    
    if (typeof window === 'undefined') return false

    try {
      // Only clean up legacy data if it exists
      this.clearAllAuthData()
      return true
    } catch (error) {
      console.error('❌ Error during session validation:', error)
      return false
    }
  },

  /**
   * @deprecated Initialize session validation - NextAuth handles this automatically
   */
  initializeSessionValidation(): void {
    console.warn('initializeSessionValidation is deprecated. NextAuth handles session management automatically.')
    
    if (typeof window === 'undefined') return

    // Only perform one-time legacy cleanup
    this.clearAllAuthData()
  }
}

export default SessionUtils