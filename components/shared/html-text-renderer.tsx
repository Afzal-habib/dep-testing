"use client";

import React from 'react';
import DOMPurify from 'dompurify';
import { cn } from '@/lib/utils';

export interface HtmlTextRendererProps {
  content?: string | null;
  maxLength?: number;
  className?: string;
  fallbackText?: string;
  showFallback?: boolean;
  renderAsHtml?: boolean; // New prop to render HTML content vs plain text
  truncateHtml?: boolean; // Whether to truncate HTML content or plain text
  preserveFormatting?: boolean;
}

/**
 * Component to safely render HTML content or convert it to plain text
 * Useful for displaying rich text content in tables or cards
 */
export function HtmlTextRenderer({
  content,
  maxLength = 100,
  className,
  fallbackText = "No description",
  showFallback = true,
  renderAsHtml = true,
  truncateHtml = false,
  preserveFormatting = false,
}: HtmlTextRendererProps) {
  // Helper function to strip HTML tags and decode entities
  const stripHtmlTags = (html: string): string => {
    // Create a temporary DOM element to parse HTML
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = html;

    // Get text content which automatically strips HTML tags
    let text = tempDiv.textContent || tempDiv.innerText || '';

    // Clean up extra whitespace and newlines
    text = text.replace(/\s+/g, ' ').trim();

    return text;
  };

  // Helper function to truncate text
  const truncateText = (text: string, length: number): string => {
    if (text.length <= length) return text;
    return text.substring(0, length).trim() + '...';
  };

  // Helper function to truncate HTML content
  const truncateHtmlContent = (html: string, maxChars: number): string => {
    const plainText = stripHtmlTags(html);
    if (plainText.length <= maxChars) return html;

    // If we need to truncate, we'll do it on the plain text and return plain text
    return truncateText(plainText, maxChars);
  };

  // Helper function to highlight @mentions in content
  const highlightMentions = (html: string): string => {
    let processedHtml = html;

    // Remove zero-width spaces used as delimiters
    processedHtml = processedHtml.replace(/\u200B/g, '');

    // Pattern 0: TipTap Mention extension format - already has proper span structure
    // These spans have data-type="mention" and data-mention-label attributes
    // Just ensure they have the mention class
    processedHtml = processedHtml.replace(
      /<span[^>]*data-type="mention"[^>]*>(.*?)<\/span>/gi,
      (match, content) => {
        // If it already has the mention class, keep it as is
        if (match.includes('class="mention"') || match.includes("class='mention'")) {
          return match;
        }
        // Add the mention class if missing
        return match.replace(/<span/, '<span class="mention"');
      }
    );

    // Pattern 1: Handle bracketed mentions [@Name] (legacy format)
    processedHtml = processedHtml.replace(/\[@([^\]]+)\]/g, (match, name) => {
      return `<span class="mention">@${name}</span>`;
    });

    // Pattern 2: Clean up escaped HTML mention spans from old messages
    processedHtml = processedHtml
      .replace(/&lt;span[^&]*class="mention"[^&]*data-user-name="([^"]*)"[^&]*&gt;[^&]*&lt;\/span&gt;/gi, '<span class="mention">@$1</span>')
      .replace(/&lt;span[^&]*class="mention"[^&]*&gt;(@[^&]+)&lt;\/span&gt;/gi, '<span class="mention">$1</span>');

    // Pattern 3: Handle @mentions with names (supports spaces via multi-word matching)
    // Match @word or @Word Word (capitalized names)
    // Only if no mention spans exist yet (to avoid double-processing)
    if (!processedHtml.includes('class="mention"')) {
      // Match @Name or @Name Name pattern (for two-word names)
      processedHtml = processedHtml.replace(/@([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|\w+)/g, (match, name) => {
        return `<span class="mention">@${name}</span>`;
      });
    }

    return processedHtml;
  };

  // Helper function to sanitize HTML content using DOMPurify
  const sanitizeHtml = (html: string): string => {
    // Use DOMPurify for robust XSS protection
    const sanitized = DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['p', 'br', 'strong', 'b', 'em', 'i', 'u', 'a', 'span', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
      ALLOWED_ATTR: ['href', 'target', 'rel', 'class', 'data-user-id', 'data-user-name', 'data-type', 'data-mention-id', 'data-mention-label', 'contenteditable', 'style'],
      ALLOW_DATA_ATTR: true,
      FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'link', 'meta', 'form', 'input', 'button'],
      FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'onchange', 'onsubmit'],
      ADD_ATTR: ['target'], // Allow target for links
      USE_PROFILES: { html: true }
    });

    // Highlight @mentions after sanitization
    return highlightMentions(sanitized);
  };

  // Process the content
  const processContent = (): { html: string; text: string; isEmpty: boolean } => {
    if (!content || content.trim() === '' || content.trim() === '<p><br></p>') {
      return { html: '', text: '', isEmpty: true };
    }

    const plainText = stripHtmlTags(content);

    if (!renderAsHtml) {
      // Return plain text version
      const truncatedText = maxLength ? truncateText(plainText, maxLength) : plainText;
      return { html: '', text: truncatedText, isEmpty: false };
    }

    // Return HTML version
    let processedHtml = sanitizeHtml(content);

    if (truncateHtml && maxLength) {
      // If we need to truncate HTML content
      if (plainText.length > maxLength) {
        const truncatedText = truncateText(plainText, maxLength);
        return { html: '', text: truncatedText, isEmpty: false };
      }
    }

    return { html: processedHtml, text: plainText, isEmpty: false };
  };

  const { html: processedHtml, text: processedText, isEmpty } = processContent();

  // If no content and fallback is disabled, return null
  if (isEmpty && !showFallback) {
    return null;
  }

  // If no content but fallback is enabled
  if (isEmpty && showFallback) {
    return (
      <span className={cn("text-sm text-muted-foreground italic", className)}>
        {fallbackText}
      </span>
    );
  }

  // Render content based on renderAsHtml flag
  if (renderAsHtml && processedHtml) {
    return (
      <div
        className={cn(
          "prose prose-sm max-w-full", // Tailwind typography classes - use max-w-full to respect parent
          "break-words [overflow-wrap:anywhere] [word-break:break-word]", // Ensure text wraps properly
          "[&>p]:my-1 [&>ol]:my-1 [&>ul]:my-1", // Reduce spacing in lists and paragraphs
          "[&>ol]:list-decimal [&>ol]:list-inside [&>ol]:pl-4", // Ordered list with numbers
          "[&>ul]:list-disc [&>ul]:list-inside [&>ul]:pl-4", // Unordered list with bullets
          "[&_ol]:list-decimal [&_ol]:list-inside", // Nested ordered lists
          "[&_ul]:list-disc [&_ul]:list-inside", // Nested unordered lists  
          "[&_li]:ml-0", // Reset list item margin
          "[&_strong]:font-semibold [&_em]:italic", // Ensure formatting works
          "[&_p]:inline", // Make paragraphs inside list items inline
          "[&_*]:max-w-full [&_*]:break-words", // Ensure all children respect width and wrap
          preserveFormatting && "whitespace-pre-wrap",
          "text-sm text-muted-foreground", // Default text styling
          className
        )}
        title={maxLength && processedText.length > maxLength ? processedText : undefined}
        dangerouslySetInnerHTML={{ __html: processedHtml }}
      />
    );
  }

  // Render as plain text
  return (
    <span
      className={cn(
        preserveFormatting && "whitespace-pre-wrap",
        "text-sm text-muted-foreground", // Default text styling
        className
      )}
      title={maxLength && processedText.length > maxLength ? processedText : undefined}
    >
      {processedText}
    </span>
  );
}

/**
 * Clean up escaped HTML entities and old mention spans from content
 */
const cleanEscapedHtml = (html: string): string => {
  return html
    // Remove zero-width spaces used as mention delimiters
    .replace(/\u200B/g, '')
    // Convert bracketed mentions [@Name] to plain @Name for text extraction
    .replace(/\[@([^\]]+)\]/g, '@$1')
    // Remove escaped HTML mention spans with data-user-name: extract the name
    .replace(/&lt;span[^&]*data-user-name="([^"]*)"[^&]*&gt;[^&]*&lt;\/span&gt;/gi, '@$1')
    // Remove escaped HTML mention spans: &lt;span class="mention"...&gt;@Name&lt;/span&gt;
    .replace(/&lt;span[^&]*class="mention"[^&]*&gt;(@[^&]+)&lt;\/span&gt;/gi, '$1')
    // Also handle regular HTML mention spans - extract text content
    .replace(/<span[^>]*class="mention"[^>]*>(@[^<]+)<\/span>/gi, '$1')
    // Decode common HTML entities
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
};

/**
 * Utility function to extract plain text from HTML content
 * Can be used outside of React components
 */
export const extractTextFromHtml = (html: string, maxLength?: number): string => {
  // First clean up any escaped HTML entities
  const cleanedHtml = cleanEscapedHtml(html);

  if (typeof window === 'undefined') {
    // Server-side fallback - basic HTML tag removal
    const text = cleanedHtml.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    return maxLength ? text.substring(0, maxLength) + (text.length > maxLength ? '...' : '') : text;
  }

  // Client-side - proper HTML parsing
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = cleanedHtml;
  let text = tempDiv.textContent || tempDiv.innerText || '';
  text = text.replace(/\s+/g, ' ').trim();

  if (maxLength && text.length > maxLength) {
    return text.substring(0, maxLength).trim() + '...';
  }

  return text;
};

/**
 * Utility function to highlight @mentions in text
 */
export const highlightMentionsInHtml = (html: string): string => {
  // First remove zero-width spaces
  let processedHtml = html.replace(/\u200B/g, '');

  // Pattern 1: Handle bracketed mentions [@Name] (legacy format)
  processedHtml = processedHtml.replace(/\[@([^\]]+)\]/g, (match, name) => {
    return `<span class="mention">@${name}</span>`;
  });

  // Pattern 2: Clean up escaped HTML mention spans from old messages
  processedHtml = processedHtml
    .replace(/&lt;span[^&]*class="mention"[^&]*data-user-name="([^"]*)"[^&]*&gt;[^&]*&lt;\/span&gt;/gi, '<span class="mention">@$1</span>')
    .replace(/&lt;span[^&]*class="mention"[^&]*&gt;(@[^&]+)&lt;\/span&gt;/gi, '<span class="mention">$1</span>');

  // Pattern 3: Handle @mentions - capture @word or @Multiple Words (capitalized words after @)
  if (!processedHtml.includes('class="mention"')) {
    // Match @followed by capitalized words (supports multi-word names like "Super Administrator")
    processedHtml = processedHtml.replace(/@([A-Z][a-zA-Z]*(?:\s+[A-Z][a-zA-Z]*)*)/g, (match, name) => {
      return `<span class="mention">@${name}</span>`;
    });
    // Also match @everyone, @here, etc. (lowercase special mentions)
    processedHtml = processedHtml.replace(/@(everyone|here|channel)/gi, (match, name) => {
      if (!processedHtml.includes(`class="mention">@${name}`)) {
        return `<span class="mention">@${name}</span>`;
      }
      return match;
    });
  }

  return processedHtml;
};

/**
 * Utility function to safely render HTML with basic sanitization
 * Can be used outside of React components
 */
export const sanitizeAndRenderHtml = (html: string): string => {
  if (typeof window === 'undefined') {
    return html; // Return as-is on server-side
  }

  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = html;

  // Remove potentially dangerous elements
  const dangerousTags = ['script', 'iframe', 'object', 'embed', 'link', 'meta'];
  dangerousTags.forEach(tag => {
    const elements = tempDiv.querySelectorAll(tag);
    elements.forEach(el => el.remove());
  });

  // Highlight @mentions
  return highlightMentionsInHtml(tempDiv.innerHTML);
};

export default HtmlTextRenderer;