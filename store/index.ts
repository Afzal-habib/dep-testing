import { configureStore } from "@reduxjs/toolkit"
import { persistStore, persistReducer } from "redux-persist"
import storage from "redux-persist/lib/storage"
import { combineReducers } from "@reduxjs/toolkit"
import authSlice from "./slices/authSlice"
import userSlice from "./slices/userSlice"
import departmentSlice from "./slices/departmentSlice"
import roleSlice from "./slices/roleSlice"
import systemPermissionSlice from "./slices/systemPermissionSlice"
import communicationSlice from "./slices/communicationSlice"
import leadSlice from "./slices/leadSlice"
import clientSlice from "./slices/clientSlice"
import projectSlice from "./slices/projectSlice"
import taskSlice from "./slices/taskSlice"
import phaseSlice from "./slices/phaseSlice"
import milestoneSlice from "./slices/milestoneSlice"
import analyticsSlice from "./slices/analyticsSlice"
import systemNotificationsSlice from "./slices/system-notifications-slice"



const rootReducer = combineReducers({
  auth: authSlice,
  users: userSlice,
  departments: departmentSlice,
  roles: roleSlice,
  systemPermissions: systemPermissionSlice,
  communications: communicationSlice,
  leads: leadSlice,
  clients: clientSlice,
  projects: projectSlice,
  tasks: taskSlice,
  phases: phaseSlice,
  milestones: milestoneSlice,
  analytics: analyticsSlice,
  systemNotifications: systemNotificationsSlice,
})


export const store = configureStore({
  reducer: rootReducer,
})


// export type RootState = ReturnType<typeof store.getState>
export type RootState = ReturnType<typeof rootReducer>
export type AppDispatch = typeof store.dispatch
