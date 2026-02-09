"use client";

import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { 
  Clock, 
  Plus, 
  Edit3, 
  Trash2, 
  Play, 
  Pause, 
  Square, 
  Calendar,
  Timer,
  CheckCircle,
  XCircle,
  MoreHorizontal 
} from "lucide-react";
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import CustomModal from "@/components/shared/custom-modal";
import { createTimeLogFormSchema, updateTimeLogFormSchema, formatHours } from "@/lib/validations/timeLog";
import type { CreateTimeLogFormData, UpdateTimeLogFormData } from "@/lib/validations/timeLog";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";

interface TimeTrackingProps {
  taskId: string;
  projectId: string;
  estimatedHours?: number;
  currentActualHours?: number;
  onTimeUpdate?: (newActualHours: number) => void;
}

interface TimeLog {
  _id: string;
  description: string;
  hours: number;
  date: string;
  startTime?: string;
  endTime?: string;
  logType: 'manual' | 'timer';
  isApproved: boolean;
  user: {
    _id: string;
    name: string;
    email: string;
    avatar?: string;
  };
  createdAt: string;
  updatedAt: string;
}

export function TimeTrackingSection({ 
  taskId, 
  projectId, 
  estimatedHours = 0,
  currentActualHours = 0,
  onTimeUpdate 
}: TimeTrackingProps) {
  const [timeLogs, setTimeLogs] = useState<TimeLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingLog, setEditingLog] = useState<TimeLog | null>(null);
  
  // Timer state
  const [isTimerRunning, setIsTimerRunning] = useState(false);
  const [timerStart, setTimerStart] = useState<Date | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [timerDescription, setTimerDescription] = useState("");

  const { toast } = useToast();

  // Forms
  const addForm = useForm<CreateTimeLogFormData>({
    resolver: zodResolver(createTimeLogFormSchema),
    defaultValues: {
      taskId,
      projectId,
      description: "",
      hours: 0,
      date: new Date().toISOString().split('T')[0],
      startTime: "",
      endTime: "",
      logType: "manual",
    },
  });

  const editForm = useForm<UpdateTimeLogFormData>({
    resolver: zodResolver(updateTimeLogFormSchema),
    defaultValues: {
      description: "",
      hours: 0,
      date: "",
      startTime: "",
      endTime: "",
    },
  });

  // Timer effect
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (isTimerRunning && timerStart) {
      interval = setInterval(() => {
        setElapsedTime(Date.now() - timerStart.getTime());
      }, 1000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isTimerRunning, timerStart]);

  // Mock data for now - in real app this would come from API
  useEffect(() => {
    // Simulate loading time logs
    setTimeLogs([
      {
        _id: '1',
        description: 'Initial setup and configuration',
        hours: 2.5,
        date: '2025-10-28',
        logType: 'manual',
        isApproved: true,
        user: {
          _id: 'user1',
          name: 'John Doe',
          email: 'john@example.com'
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
      {
        _id: '2',
        description: 'Bug fixes and testing',
        hours: 1.75,
        date: '2025-10-27',
        logType: 'timer',
        isApproved: false,
        user: {
          _id: 'user2',
          name: 'Jane Smith',
          email: 'jane@example.com'
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ]);
  }, []);

  const totalLoggedHours = timeLogs.reduce((total, log) => total + log.hours, 0);
  const progressPercentage = estimatedHours > 0 ? (totalLoggedHours / estimatedHours) * 100 : 0;

  // Timer functions
  const startTimer = () => {
    setTimerStart(new Date());
    setIsTimerRunning(true);
    setElapsedTime(0);
  };

  const pauseTimer = () => {
    setIsTimerRunning(false);
  };

  const stopTimer = () => {
    if (timerStart && elapsedTime > 0) {
      const hours = elapsedTime / (1000 * 60 * 60);
      
      // Auto-create time log from timer
      const newLog: TimeLog = {
        _id: Date.now().toString(),
        description: timerDescription || 'Timed work session',
        hours: Math.round(hours * 100) / 100,
        date: new Date().toISOString().split('T')[0],
        startTime: timerStart.toISOString(),
        endTime: new Date().toISOString(),
        logType: 'timer',
        isApproved: false,
        user: {
          _id: 'current-user',
          name: 'Current User',
          email: 'current@example.com'
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      
      setTimeLogs(prev => [newLog, ...prev]);
      onTimeUpdate?.(totalLoggedHours + newLog.hours);
    }
    
    setIsTimerRunning(false);
    setTimerStart(null);
    setElapsedTime(0);
    setTimerDescription("");
  };

  // Format elapsed time
  const formatElapsedTime = (ms: number) => {
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  };

  // Handle add time log
  const handleAddTimeLog = async (data: CreateTimeLogFormData) => {
    try {
      setLoading(true);
      
      // Mock API call - in real app this would call the actual API
      const hours = typeof data.hours === 'string' ? parseFloat(data.hours) : (data.hours as number);
      const newLog: TimeLog = {
        _id: Date.now().toString(),
        description: data.description,
        hours,
        date: data.date,
        startTime: data.startTime,
        endTime: data.endTime,
        logType: data.logType,
        isApproved: false,
        user: {
          _id: 'current-user',
          name: 'Current User',
          email: 'current@example.com'
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      
      setTimeLogs(prev => [newLog, ...prev]);
      onTimeUpdate?.(totalLoggedHours + newLog.hours);
      setShowAddModal(false);
      addForm.reset();
      
      toast({
        title: "Success",
        description: "Time log added successfully",
      });
    } catch (error) {
      console.error('Error adding time log:', error);
      toast({
        title: "Error",
        description: "Failed to add time log",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  // Handle edit time log
  const handleEditTimeLog = async (data: UpdateTimeLogFormData) => {
    if (!editingLog) return;
    
    try {
      setLoading(true);
      
      // Mock API call
      const hours = data.hours !== undefined 
        ? (typeof data.hours === 'string' ? parseFloat(data.hours) : (data.hours as number))
        : editingLog.hours;
      setTimeLogs(prev => prev.map(log => 
        log._id === editingLog._id 
          ? { 
              ...log, 
              description: data.description || log.description,
              hours,
              date: data.date || log.date,
              updatedAt: new Date().toISOString(),
            }
          : log
      ));
      
      setEditingLog(null);
      editForm.reset();
      
      toast({
        title: "Success",
        description: "Time log updated successfully",
      });
    } catch (error) {
      console.error('Error updating time log:', error);
      toast({
        title: "Error",
        description: "Failed to update time log",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  // Handle delete time log
  const handleDeleteTimeLog = async (logId: string) => {
    try {
      setTimeLogs(prev => prev.filter(log => log._id !== logId));
      
      toast({
        title: "Success",
        description: "Time log deleted successfully",
      });
    } catch (error) {
      console.error('Error deleting time log:', error);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-semibold">Time Tracking</h3>
          </div>
          <Button onClick={() => setShowAddModal(true)} size="sm">
            <Plus className="h-4 w-4 mr-1" />
            Log Time
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Time Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-muted rounded-lg border border-border">
            <div className="text-2xl font-bold text-primary">{formatHours(estimatedHours)}</div>
            <div className="text-sm text-muted-foreground">Estimated</div>
          </div>
          <div className="text-center p-4 bg-muted rounded-lg border border-border">
            <div className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">{formatHours(totalLoggedHours)}</div>
            <div className="text-sm text-muted-foreground">Logged</div>
          </div>
          <div className="text-center p-4 bg-muted rounded-lg border border-border">
            <div className="text-2xl font-bold text-amber-600 dark:text-amber-400">
              {estimatedHours > 0 ? `${Math.round(progressPercentage)}%` : 'N/A'}
            </div>
            <div className="text-sm text-muted-foreground">Progress</div>
          </div>
        </div>

        {/* Progress Bar */}
        {estimatedHours > 0 && (
          <div className="w-full">
            <div className="flex justify-between text-sm text-muted-foreground mb-2">
              <span>Progress</span>
              <span>{Math.round(progressPercentage)}% of estimated time</span>
            </div>
            <div className="w-full bg-muted rounded-full h-2">
              <div 
                className={`h-2 rounded-full transition-all duration-300 ${
                  progressPercentage > 100 ? 'bg-destructive' : 
                  progressPercentage > 80 ? 'bg-amber-500' : 
                  'bg-emerald-500'
                }`}
                style={{ width: `${Math.min(progressPercentage, 100)}%` }}
              />
            </div>
          </div>
        )}

        {/* Timer Section */}
        <div className="p-4 bg-muted/50 rounded-lg border border-border">
          <div className="flex items-center justify-between mb-4">
            <h4 className="font-semibold flex items-center gap-2">
              <Timer className="h-4 w-4 text-primary" />
              Timer
            </h4>
            <div className="text-2xl font-mono font-bold text-primary">
              {formatElapsedTime(elapsedTime)}
            </div>
          </div>
          
          <div className="flex items-center gap-3 mb-3">
            <Input
              placeholder="What are you working on?"
              value={timerDescription}
              onChange={(e) => setTimerDescription(e.target.value)}
              disabled={isTimerRunning}
              className="flex-1"
            />
          </div>
          
          <div className="flex items-center gap-2">
            {!isTimerRunning && !timerStart && (
              <Button onClick={startTimer} className="bg-emerald-600 hover:bg-emerald-700 text-white">
                <Play className="h-4 w-4 mr-1" />
                Start
              </Button>
            )}
            
            {isTimerRunning && (
              <Button onClick={pauseTimer} variant="outline">
                <Pause className="h-4 w-4 mr-1" />
                Pause
              </Button>
            )}
            
            {timerStart && (
              <Button onClick={stopTimer} variant="destructive">
                <Square className="h-4 w-4 mr-1" />
                Stop & Save
              </Button>
            )}
          </div>
        </div>

        <Separator />

        {/* Time Logs List */}
        <div className="space-y-3">
          <h4 className="font-semibold">Time Logs ({timeLogs.length})</h4>
          
          {timeLogs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Clock className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No time logs yet</p>
              <p className="text-sm">Start tracking your time!</p>
            </div>
          ) : (
            timeLogs.map((log) => (
              <Card key={log._id} className="border-l-4 border-l-primary/30 hover:shadow-md transition-shadow group">
                <CardContent className="pt-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div className="flex items-center gap-2">
                          <Badge variant={log.logType === 'timer' ? 'default' : 'secondary'} className="text-xs">
                            {log.logType === 'timer' ? (
                              <>
                                <Timer className="h-3 w-3 mr-1" />
                                Timer
                              </>
                            ) : (
                              <>
                                <Edit3 className="h-3 w-3 mr-1" />
                                Manual
                              </>
                            )}
                          </Badge>
                          <Badge variant={log.isApproved ? 'default' : 'secondary'}>
                            {log.isApproved ? (
                              <>
                                <CheckCircle className="h-3 w-3 mr-1" />
                                Approved
                              </>
                            ) : (
                              <>
                                <XCircle className="h-3 w-3 mr-1" />
                                Pending
                              </>
                            )}
                          </Badge>
                        </div>
                        <div className="text-lg font-semibold text-primary">
                          {formatHours(log.hours)}
                        </div>
                      </div>
                      
                      <p className="text-sm text-foreground mb-2">{log.description}</p>
                      
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />
                          {new Date(log.date).toLocaleDateString()}
                        </span>
                        <span>by {log.user.name}</span>
                        <span>{formatDistanceToNow(new Date(log.createdAt), { addSuffix: true })}</span>
                      </div>
                    </div>

                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          setEditingLog(log);
                          editForm.reset({
                            description: log.description,
                            hours: log.hours || 0,
                            date: log.date,
                          });
                        }}>
                          <Edit3 className="h-4 w-4 mr-2" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          onClick={() => handleDeleteTimeLog(log._id)}
                          className="text-destructive"
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </CardContent>

      {/* Add Time Log Modal */}
      <CustomModal
        isOpen={showAddModal}
        onClose={() => {
          setShowAddModal(false);
          addForm.reset();
        }}
        title="Add Time Log"
        modalSize="md"
      >
        <form onSubmit={addForm.handleSubmit(handleAddTimeLog)} className="space-y-4">
          <div>
            <Label>Description</Label>
            <Textarea
              {...addForm.register("description")}
              placeholder="Describe what you worked on..."
              rows={3}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Hours</Label>
              <Input
                {...addForm.register("hours")}
                type="number"
                step="0.25"
                placeholder="2.5"
              />
            </div>
            <div>
              <Label>Date</Label>
              <Input
                {...addForm.register("date")}
                type="date"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Start Time (Optional)</Label>
              <Input
                {...addForm.register("startTime")}
                type="time"
              />
            </div>
            <div>
              <Label>End Time (Optional)</Label>
              <Input
                {...addForm.register("endTime")}
                type="time"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setShowAddModal(false);
                addForm.reset();
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              Add Time Log
            </Button>
          </div>
        </form>
      </CustomModal>

      {/* Edit Time Log Modal */}
      <CustomModal
        isOpen={!!editingLog}
        onClose={() => {
          setEditingLog(null);
          editForm.reset();
        }}
        title="Edit Time Log"
        modalSize="md"
      >
        <form onSubmit={editForm.handleSubmit(handleEditTimeLog)} className="space-y-4">
          <div>
            <Label>Description</Label>
            <Textarea
              {...editForm.register("description")}
              placeholder="Describe what you worked on..."
              rows={3}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Hours</Label>
              <Input
                {...editForm.register("hours")}
                type="number"
                step="0.25"
                placeholder="2.5"
              />
            </div>
            <div>
              <Label>Date</Label>
              <Input
                {...editForm.register("date")}
                type="date"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setEditingLog(null);
                editForm.reset();
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              Update Time Log
            </Button>
          </div>
        </form>
      </CustomModal>
    </Card>
  );
}