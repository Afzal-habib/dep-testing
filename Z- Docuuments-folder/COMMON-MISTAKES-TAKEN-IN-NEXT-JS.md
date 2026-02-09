# 1: "use client" too high
# 2: Not refactoring for "use client"
# 3: Thinking a component is a server component because it does not have "use client"
# 4: Thinking that a server component becomes a client component if you wrap it inside a client component
# 5: Using state management (Context API, Zustand, Redux) in server components 
# 6: Using ‘use server’ to create a server component
# 7: Accidentally leaking sensitive data from server to client
# 8: Thinking that client components only run in the client
# 9: Using browser API’s (e.g. localStorage) incorrectly
# 10: Getting hydration errors
# 11: Incorrectly dealing with third-party components
# 12: Using route handlers for getting data
# 13: Thinking it’s a problem to get the same data in different places
# 14: Getting a ‘waterfall’ effect when fetching data
# 15: Submitting data to server component or route handler
# 16: Getting confused when the page doesn’t reflect data mutation
 # 17: Thinking that server actions can only be used in server components
 # 18: Forgetting to validate & protect server actions
 # 19: Adding ‘use server’ to make sure something stays on the server
 # 20: Misunderstanding dynamic routes (params & searchParams)
 # 21: Incorrectly working with searchParams
 # 22: Forgetting to deal with loading state
 # 23: Not being granular with Suspense
 # 24: Adding Suspense in the wrong place
 # 25: Forgetting ‘key’ prop for Suspense
 # 26: Accidentally opting a page out of static rendering
 # 27: Hardcoding secrets
 # 28: Not making a distinction between client and server utils
 # 29: Using redirect() in try / catch