"use client";

import React from 'react';
import { UseFormReturn } from 'react-hook-form';
import {
  FormField,
  FormItem,
  FormLabel,
  FormControl,
  FormMessage,
} from '@/components/ui/form';
import RichTextEditor from './rich-text-editor';
import { cn } from '@/lib/utils';

export interface RichTextFormFieldProps {
  form: UseFormReturn<any>;
  name: string;
  label: string;
  placeholder?: string;
  description?: string;
  required?: boolean;
  disabled?: boolean;
  className?: string;
  height?: string | number;
  showToolbar?: boolean;
}

export function RichTextFormField({
  form,
  name,
  label,
  placeholder,
  description,
  required = false,
  disabled = false,
  className,
  height = '150px',
  showToolbar = true,
}: RichTextFormFieldProps) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field, fieldState }) => (
        <FormItem className={className}>
          <FormLabel className={required ? "after:content-['*'] after:ml-0.5 after:text-destructive" : ""}>
            {label}
          </FormLabel>
          <FormControl>
            <RichTextEditor
              value={field.value || ''}
              onChange={field.onChange}
              placeholder={placeholder}
              disabled={disabled}
              height={height}
              showToolbar={showToolbar}
              error={!!fieldState.error}
            />
          </FormControl>
          {description && (
            <p className="text-sm text-muted-foreground mt-1">
              {description}
            </p>
          )}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

export default RichTextFormField;