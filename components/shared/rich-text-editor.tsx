"use client";

import React, { forwardRef, useImperativeHandle, useCallback, useEffect } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import Document from '@tiptap/extension-document';
import Paragraph from '@tiptap/extension-paragraph';
import Text from '@tiptap/extension-text';
import Bold from '@tiptap/extension-bold';
import Italic from '@tiptap/extension-italic';
import Strike from '@tiptap/extension-strike';
import Heading from '@tiptap/extension-heading';
import Blockquote from '@tiptap/extension-blockquote';
import CodeBlock from '@tiptap/extension-code-block';
import History from '@tiptap/extension-history';
import { Link } from '@tiptap/extension-link';
import { TextAlign } from '@tiptap/extension-text-align';
import { Color } from '@tiptap/extension-color';
import { TextStyle } from '@tiptap/extension-text-style';
import BulletList from '@tiptap/extension-bullet-list';
import OrderedList from '@tiptap/extension-ordered-list';
import ListItem from '@tiptap/extension-list-item';
import { cn } from '@/lib/utils';
import { 
  Bold as BoldIcon, 
  Italic as ItalicIcon, 
  Strikethrough, 
  List, 
  ListOrdered,
  AlignLeft,
  AlignCenter,
  AlignRight,
  Link as LinkIcon,
  Quote,
  Code,
  Undo,
  Redo
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';

export interface RichTextEditorProps {
  value?: string;
  onChange?: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  readOnly?: boolean;
  className?: string;
  height?: string | number;
  error?: boolean;
  id?: string;
  showToolbar?: boolean;
}

export interface RichTextEditorRef {
  focus: () => void;
  blur: () => void;
  getEditor: () => any;
}

const RichTextEditor = forwardRef<RichTextEditorRef, RichTextEditorProps>(
  ({
    value = '',
    onChange,
    placeholder = 'Enter text...',
    disabled = false,
    readOnly = false,
    className,
    height = '150px',
    error = false,
    id,
    showToolbar = true,
    ...props
  }, ref) => {
    const editor = useEditor({
      extensions: [
        // Core extensions
        Document,
        Paragraph,
        Text,
        
        // Formatting extensions
        Bold,
        Italic,
        Strike,
        
        // Structure extensions
        Heading.configure({
          levels: [1, 2, 3, 4, 5, 6],
        }),
        Blockquote,
        CodeBlock,
        
        // List extensions with explicit configuration
        ListItem,
        BulletList.configure({
          HTMLAttributes: {
            class: 'bullet-list',
          },
        }),
        OrderedList.configure({
          HTMLAttributes: {
            class: 'ordered-list',
          },
        }),
        
        // Additional extensions
        Link.configure({
          openOnClick: false,
        }),
        TextAlign.configure({
          types: ['heading', 'paragraph'],
        }),
        Color,
        TextStyle,
        History.configure({
          depth: 10,
        }),
      ],
      content: value || '',
      editable: !disabled && !readOnly,
      immediatelyRender: false, // Fix SSR issue
      onUpdate: ({ editor }) => {
        const html = editor.getHTML();
        const isEmpty = editor.getText().trim() === '';
        onChange?.(isEmpty ? '' : html);
      },
    });

    // Update editor content when value prop changes
    useEffect(() => {
      if (editor && value !== editor.getHTML()) {
        editor.commands.setContent(value || '');
      }
    }, [editor, value]);

    // Update editable state when disabled/readOnly changes
    useEffect(() => {
      if (editor) {
        editor.setEditable(!disabled && !readOnly);
      }
    }, [editor, disabled, readOnly]);

    // Expose methods via ref
    useImperativeHandle(ref, () => ({
      focus: () => {
        editor?.commands.focus();
      },
      blur: () => {
        editor?.commands.blur();
      },
      getEditor: () => {
        return editor;
      }
    }), [editor]);

    const addLink = useCallback(() => {
      const previousUrl = editor?.getAttributes('link').href;
      const url = window.prompt('URL', previousUrl);

      if (url === null) {
        return;
      }

      if (url === '') {
        editor?.chain().focus().extendMarkRange('link').unsetLink().run();
        return;
      }

      editor?.chain().focus().extendMarkRange('link').setLink({ href: url }).run();
    }, [editor]);

    const toggleBulletList = useCallback(() => {
      if (!editor) return;
      editor.chain().focus().toggleBulletList().run();
    }, [editor]);

    const toggleOrderedList = useCallback(() => {
      if (!editor) return;
      editor.chain().focus().toggleOrderedList().run();
    }, [editor]);

    if (!editor) {
      return (
        <div className="h-32 bg-muted animate-pulse rounded-md flex items-center justify-center">
          <div className="text-sm text-muted-foreground">Loading editor...</div>
        </div>
      );
    }

    const editorStyles = {
      '--editor-height': typeof height === 'number' ? `${height}px` : height,
    } as React.CSSProperties;

    return (
      <div 
        className={cn(
          'rich-text-editor border rounded-md',
          {
            'border-destructive': error,
            'opacity-50': disabled,
          },
          className
        )}
        style={editorStyles}
      >
        {showToolbar && (
          <div className="border-b p-2 flex items-center gap-1 flex-wrap bg-background">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().toggleBold().run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('bold') && 'bg-accent'
              )}
              disabled={disabled}
              title="Bold"
            >
              <BoldIcon className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().toggleItalic().run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('italic') && 'bg-accent'
              )}
              disabled={disabled}
              title="Italic"
            >
              <ItalicIcon className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().toggleStrike().run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('strike') && 'bg-accent'
              )}
              disabled={disabled}
              title="Strikethrough"
            >
              <Strikethrough className="h-4 w-4" />
            </Button>

            <Separator orientation="vertical" className="h-6 mx-1" />

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={toggleBulletList}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('bulletList') && 'bg-accent'
              )}
              disabled={disabled}
              title="Bullet List"
            >
              <List className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={toggleOrderedList}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('orderedList') && 'bg-accent'
              )}
              disabled={disabled}
              title="Numbered List"
            >
              <ListOrdered className="h-4 w-4" />
            </Button>

            <Separator orientation="vertical" className="h-6 mx-1" />

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().setTextAlign('left').run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive({ textAlign: 'left' }) && 'bg-accent'
              )}
              disabled={disabled}
            >
              <AlignLeft className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().setTextAlign('center').run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive({ textAlign: 'center' }) && 'bg-accent'
              )}
              disabled={disabled}
            >
              <AlignCenter className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().setTextAlign('right').run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive({ textAlign: 'right' }) && 'bg-accent'
              )}
              disabled={disabled}
            >
              <AlignRight className="h-4 w-4" />
            </Button>

            <Separator orientation="vertical" className="h-6 mx-1" />

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().toggleBlockquote().run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('blockquote') && 'bg-accent'
              )}
              disabled={disabled}
            >
              <Quote className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().toggleCodeBlock().run()}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('codeBlock') && 'bg-accent'
              )}
              disabled={disabled}
            >
              <Code className="h-4 w-4" />
            </Button>

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={addLink}
              className={cn(
                'h-8 w-8 p-0',
                editor.isActive('link') && 'bg-accent'
              )}
              disabled={disabled}
            >
              <LinkIcon className="h-4 w-4" />
            </Button>

            <Separator orientation="vertical" className="h-6 mx-1" />

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().undo().run()}
              className="h-8 w-8 p-0"
              disabled={disabled || !editor.can().chain().focus().undo().run()}
            >
              <Undo className="h-4 w-4" />
            </Button>
            
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => editor.chain().focus().redo().run()}
              className="h-8 w-8 p-0"
              disabled={disabled || !editor.can().chain().focus().redo().run()}
            >
              <Redo className="h-4 w-4" />
            </Button>
          </div>
        )}
        
        <div className="relative">
          <EditorContent
            editor={editor}
            id={id}
            className={cn(
              'prose prose-sm max-w-none p-3 focus-within:outline-none',
              '[&_.ProseMirror]:outline-none [&_.ProseMirror]:min-h-[var(--editor-height)]',
              '[&_.ProseMirror]:text-foreground [&_.ProseMirror]:bg-background',
              '[&_.ProseMirror_p.is-editor-empty:first-child::before]:content-[attr(data-placeholder)]',
              '[&_.ProseMirror_p.is-editor-empty:first-child::before]:text-muted-foreground',
              '[&_.ProseMirror_p.is-editor-empty:first-child::before]:pointer-events-none',
              '[&_.ProseMirror_p.is-editor-empty:first-child::before]:float-left',
              '[&_.ProseMirror_p.is-editor-empty:first-child::before]:h-0',
              // List styling
              '[&_.ProseMirror_ul]:list-disc [&_.ProseMirror_ul]:ml-6 [&_.ProseMirror_ul]:my-2',
              '[&_.ProseMirror_ol]:list-decimal [&_.ProseMirror_ol]:ml-6 [&_.ProseMirror_ol]:my-2',
              '[&_.ProseMirror_li]:my-1',
              '[&_.ProseMirror_ul_ul]:list-[circle] [&_.ProseMirror_ul_ul_ul]:list-[square]',
              '[&_.ProseMirror_blockquote]:border-l-4 [&_.ProseMirror_blockquote]:border-border [&_.ProseMirror_blockquote]:pl-4 [&_.ProseMirror_blockquote]:ml-0 [&_.ProseMirror_blockquote]:italic',
              '[&_.ProseMirror_pre]:bg-muted [&_.ProseMirror_pre]:p-4 [&_.ProseMirror_pre]:rounded [&_.ProseMirror_pre]:overflow-x-auto',
              '[&_.ProseMirror_code]:bg-muted [&_.ProseMirror_code]:px-1 [&_.ProseMirror_code]:rounded [&_.ProseMirror_code]:text-sm',
              readOnly && 'cursor-default',
              disabled && 'opacity-50 cursor-not-allowed'
            )}
            data-placeholder={placeholder}
            {...props}
          />
        </div>
      </div>
    );
  }
);

RichTextEditor.displayName = 'RichTextEditor';

export default RichTextEditor;