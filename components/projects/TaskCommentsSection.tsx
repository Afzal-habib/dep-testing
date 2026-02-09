"use client";

import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import {
  MessageCircle,
  Send,
  Edit3,
  Trash2,
  Reply,
  Clock,
  User,
  AtSign,
  MoreHorizontal
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useComments } from "@/hooks/use-comments";
import { useUsers } from "@/hooks/use-users";
import { useAuthUser } from "@/hooks/use-auth-user";
import { createCommentFormSchema, updateCommentFormSchema } from "@/lib/validations/comment";
import type { CreateCommentFormData, UpdateCommentFormData } from "@/lib/validations/comment";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";
import RichTextEditor from "../shared/rich-text-editor";
import HtmlTextRenderer from "../shared/html-text-renderer";

interface TaskCommentsSectionProps {
  taskId: string;
  projectId: string;
  departmentId: string;
}

interface CommentItemProps {
  comment: any;
  onEdit: (comment: any) => void;
  onDelete: (commentId: string) => void;
  onReply: (comment: any) => void;
  currentUserId: string;
  level?: number;
}

function CommentItem({
  comment,
  onEdit,
  onDelete,
  onReply,
  currentUserId,
  level = 0
}: CommentItemProps) {
  const isAuthor = comment.authorId === currentUserId;
  const isEdited = comment.isEdited;

  return (
    <div className={`${level > 0 ? 'ml-6 pl-4 border-l-2 border-primary/30 rounded-r-lg' : ''}`}>
      <div className="group relative">
        <Card className={`
          ${isAuthor
            ? 'border-l-4 border-l-primary shadow-sm'
            : 'border-l-4 border-l-accent/50'
          }
          hover:shadow-lg hover:border-l-primary/70 transition-all duration-300 transform hover:-translate-y-0.5
        `}>
          <CardContent className="p-2">
            {/* Comment Header */}
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-3">
                <Avatar className="h-10 w-10 ring-2 ring-primary/20 hover:ring-primary/40 transition-all">
                  <AvatarImage src={comment.author?.avatar} alt={comment.author?.name} />
                  <AvatarFallback className="text-sm font-bold bg-gradient-to-br from-primary to-accent text-white">
                    {comment.author?.name ? (() => {
                      const parts = comment.author.name.trim().split(' ');
                      if (parts.length === 1) {
                        return parts[0][0].toUpperCase();
                      }
                      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                    })()
                  : ''}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-sm font-semibold text-foreground">{comment.author?.name}</p>
                    {isAuthor && <Badge variant="secondary" className="text-xs bg-primary/10 text-primary border-primary/30">You</Badge>}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Clock className="h-3 w-3" />
                    <span>{formatDistanceToNow(new Date(comment.createdAt), { addSuffix: true })}</span>
                    {isEdited && (
                      <>
                        <span>•</span>
                        <span className="text-orange-600 font-medium">edited</span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Action Menu */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-all duration-200 hover:bg-primary/10 rounded-full"
                  >
                    <MoreHorizontal className="h-4 w-4 text-muted-foreground hover:text-primary" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48 shadow-lg">
                  <DropdownMenuItem
                    onClick={() => onReply(comment)}
                    className="flex items-center gap-2 hover:bg-primary/10 cursor-pointer"
                  >
                    <Reply className="h-4 w-4 text-primary" />
                    Reply
                  </DropdownMenuItem>
                  {isAuthor && (
                    <>
                      <DropdownMenuItem
                        onClick={() => onEdit(comment)}
                        className="flex items-center gap-2 hover:bg-orange-50 cursor-pointer"
                      >
                        <Edit3 className="h-4 w-4 text-orange-500" />
                        Edit
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => comment?._id && onDelete(comment._id)}
                        className="text-destructive hover:bg-destructive/10 cursor-pointer"
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Delete
                      </DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            {/* Comment Content */}
            <div className="prose prose-sm max-w-none">
              <HtmlTextRenderer
                content={comment.content}
                maxLength={120}
                className="line-clamp-3"
                fallbackText="No description"
                showFallback={true}
                renderAsHtml={true}
                truncateHtml={true}
              />
            </div>

            {/* Mentions */}
            {comment.mentionedUsers && comment.mentionedUsers.length > 0 && (
              <div className="mt-3 flex items-center gap-2 flex-wrap p-2 bg-primary/5 rounded-lg border border-primary/20">
                <AtSign className="h-3 w-3 text-primary" />
                <span className="text-xs text-muted-foreground font-medium">Mentioned:</span>
                {comment.mentionedUsers.map((user: any) => (
                  <Badge key={user._id} variant="secondary" className="text-xs bg-primary/10 text-primary border-primary/30 hover:bg-primary/20">
                    @{user.name}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Replies */}
        {comment.replies && comment.replies.length > 0 && (
          <div className="mt-3 space-y-2">
            {comment.replies.map((reply: any, ridx: number) => (
              <CommentItem
                key={reply?._id ?? `reply-${ridx}-${comment._id ?? 'noid'}`}
                comment={reply}
                onEdit={onEdit}
                onDelete={onDelete}
                onReply={onReply}
                currentUserId={currentUserId}
                level={level + 1}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function TaskCommentsSection({ taskId, projectId, departmentId }: TaskCommentsSectionProps) {
  const [editingComment, setEditingComment] = useState<any>(null);
  const [replyingTo, setReplyingTo] = useState<any>(null);
  const [showMentions, setShowMentions] = useState(false);

  const { user: currentUser } = useAuthUser();
  const { users } = useUsers();
  const { toast } = useToast();

  const {
    useTaskComments,
    createComment,
    updateComment,
    deleteComment,
    replyToComment,
    creating,
    updating,
    deleting
  } = useComments();

  // Fetch comments for this task
  const { data: comments = [], isLoading, refetch } = useTaskComments(taskId, projectId);

  // Create comment form
  const createForm = useForm<CreateCommentFormData>({
    resolver: zodResolver(createCommentFormSchema),
    defaultValues: {
      content: "",
      taskId,
      projectId,
      mentions: [],
      parentCommentId: undefined,
    },
  });

  // Update comment form
  const updateForm = useForm<UpdateCommentFormData>({
    resolver: zodResolver(updateCommentFormSchema),
    defaultValues: {
      content: "",
      mentions: [],
    },
  });

  // Filter users by department for mentions
  const departmentUsers = users.filter(user => {
    const userDeptId = typeof user.department === 'string' ? user.department : user.department?._id;
    return userDeptId === departmentId && user.status === 'active';
  });

  // Handle create comment
  const handleCreateComment = async (data: CreateCommentFormData) => {
    try {
      await createComment({
        ...data,
        taskId,
        projectId,
        parentCommentId: replyingTo?._id,
      });

      createForm.reset();
      setReplyingTo(null);

      toast({
        title: "Success",
        description: "Comment added successfully",
      });
    } catch (error) {
      console.error('Error creating comment:', error);
    }
  };

  // Handle update comment
  const handleUpdateComment = async (data: UpdateCommentFormData) => {
    if (!editingComment) return;

    try {
      await updateComment(editingComment._id, data);
      setEditingComment(null);
      updateForm.reset();

      toast({
        title: "Success",
        description: "Comment updated successfully",
      });
    } catch (error) {
      console.error('Error updating comment:', error);
    }
  };

  // Handle delete comment
  const handleDeleteComment = async (commentId: string) => {
    try {
      await deleteComment(commentId);

      toast({
        title: "Success",
        description: "Comment deleted successfully",
      });
    } catch (error) {
      console.error('Error deleting comment:', error);
    }
  };

  // Set up edit mode
  const handleEdit = (comment: any) => {
    setEditingComment(comment);
    updateForm.setValue('content', comment.content);
    setReplyingTo(null);
  };

  // Set up reply mode
  const handleReply = (comment: any) => {
    setReplyingTo(comment);
    setEditingComment(null);
    createForm.setValue('content', `@${comment.author?.name} `);
  };

  // Cancel edit/reply
  const handleCancel = () => {
    setEditingComment(null);
    setReplyingTo(null);
    createForm.reset();
    updateForm.reset();
  };

  if (isLoading) {
    return (
      <Card className="border-primary/20 shadow-lg">
        <CardHeader className="bg-gradient-to-r from-primary/5 to-accent/5 border-b border-primary/10">
          <div className="flex items-center gap-2">
            <MessageCircle className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-semibold text-foreground">Comments</h3>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-12">
            <div className="text-center space-y-3">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-primary/20 border-t-primary mx-auto"></div>
              <p className="text-muted-foreground">Loading comments...</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-primary/20 shadow-lg">
      <CardHeader className="bg-gradient-to-r from-primary/5 to-accent/5 border-b border-primary/10 py-2 px-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg">
              <MessageCircle className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-foreground">Comments</h3>
              <p className="text-sm text-muted-foreground">Collaborate and discuss task progress</p>
            </div>
          </div>
          <Badge variant="secondary" className="bg-primary/10 text-primary border-primary/20">
            {comments.length} {comments.length === 1 ? 'comment' : 'comments'}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-6 px-4">
        {/* Comment Form */}
        <div className="space-y-4">
          {replyingTo && (
            <div className="p-4 bg-gradient-to-r from-primary/5 to-accent/5 border border-primary/20 rounded-lg">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Reply className="h-4 w-4 text-primary" />
                  <p className="text-sm text-foreground">
                    Replying to <span className="font-semibold text-primary">{replyingTo.author?.name}</span>
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleCancel}
                  className="h-8 px-3 hover:bg-destructive/10 hover:text-destructive"
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {editingComment && (
            <div className="p-4 bg-gradient-to-r from-orange-50 to-orange-25 border border-orange-200 rounded-lg">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Edit3 className="h-4 w-4 text-orange-500" />
                  <p className="text-sm text-orange-700 font-medium">
                    Editing comment
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleCancel}
                  className="h-8 px-3 hover:bg-destructive/10 hover:text-destructive"
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}

          <form
            onSubmit={editingComment
              ? updateForm.handleSubmit(handleUpdateComment)
              : createForm.handleSubmit(handleCreateComment)
            }
            className="mt-4"
          >
            <div>
              <Label htmlFor="comment" className="mb-4">
                {editingComment ? 'Update your comment' : 'Add a comment'}:
              </Label>
              <RichTextEditor
                value={(editingComment ? updateForm.watch('content') : createForm.watch('content')) || ''}
                onChange={(value: any) => {
                  if (editingComment) {
                    updateForm.setValue('content', value);
                  } else {
                    createForm.setValue('content', value);
                  }
                }}
                placeholder="Write your comment here... Use @username to mention team members"
                disabled={creating || updating}
                height="150px"
              />
            </div>

            <div className="flex items-center justify-between mt-2">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <AtSign className="h-3 w-3" />
                <span>Use @ to mention team members</span>
              </div>

              <div className="flex items-center gap-2">
                {(editingComment || replyingTo) && (
                  <Button type="button" variant="outline" onClick={handleCancel}>
                    Cancel
                  </Button>
                )}
                <Button
                  type="submit"
                  disabled={creating || updating}
                  className="flex items-center gap-2"
                >
                  <Send className="h-4 w-4" />
                  {editingComment ? 'Update' : replyingTo ? 'Reply' : 'Comment'}
                </Button>
              </div>
            </div>
          </form>
        </div>

        <Separator />

        {/* Comments List */}
        <div className="space-y-4">
          {comments.length === 0 ? (
            <div className="text-center py-4 text-muted-foreground">
              <MessageCircle className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No comments yet</p>
              <p className="text-sm">Be the first to add a comment!</p>
            </div>
          ) : (
            comments.filter(Boolean).map((comment: any, idx: number) => (
             <div className="col-span-6" key={comment?._id ?? `comment-wrapper-${idx}`}>
               <CommentItem
                key={comment?._id ?? `comment-${idx}`}
                comment={comment}
                onEdit={handleEdit}
                onDelete={handleDeleteComment}
                onReply={handleReply}
                currentUserId={currentUser?.id || ''}
               
              />
             </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}