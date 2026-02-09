/**
 * TipTap Mention Extension for WhatsApp-style mentions
 * 
 * This creates atomic mention nodes that:
 * 1. Display with proper styling regardless of name length
 * 2. Delete as a complete unit (not character by character)
 * 3. Are non-editable once inserted
 */

import { Node, mergeAttributes } from '@tiptap/core'

export interface MentionOptions {
  HTMLAttributes: Record<string, any>
  renderLabel: (props: { options: MentionOptions; node: any }) => string
}

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    mention: {
      /**
       * Insert a mention node
       */
      insertMention: (attributes: { id: string; label: string }) => ReturnType
    }
  }
}

export const Mention = Node.create<MentionOptions>({
  name: 'mention',

  addOptions() {
    return {
      HTMLAttributes: {},
      renderLabel({ node }) {
        return `@${node.attrs.label ?? node.attrs.id}`
      },
    }
  },

  group: 'inline',

  inline: true,

  selectable: true,

  // This makes the mention delete as a single unit
  atom: true,

  addAttributes() {
    return {
      id: {
        default: null,
        parseHTML: element => element.getAttribute('data-mention-id'),
        renderHTML: attributes => {
          if (!attributes.id) {
            return {}
          }
          return {
            'data-mention-id': attributes.id,
          }
        },
      },
      label: {
        default: null,
        parseHTML: element => element.getAttribute('data-mention-label'),
        renderHTML: attributes => {
          if (!attributes.label) {
            return {}
          }
          return {
            'data-mention-label': attributes.label,
          }
        },
      },
    }
  },

  parseHTML() {
    return [
      {
        tag: `span[data-type="${this.name}"]`,
      },
    ]
  },

  renderHTML({ node, HTMLAttributes }) {
    return [
      'span',
      mergeAttributes(
        { 'data-type': this.name },
        this.options.HTMLAttributes,
        HTMLAttributes,
        {
          class: 'mention',
          contenteditable: 'false',
        }
      ),
      this.options.renderLabel({ options: this.options, node }),
    ]
  },

  renderText({ node }) {
    return this.options.renderLabel({ options: this.options, node })
  },

  addCommands() {
    return {
      insertMention:
        (attributes) =>
        ({ chain, state }) => {
          const { selection } = state
          const { $from, empty } = selection

          // Check for partial @query text to delete
          if (empty) {
            const textBefore = $from.nodeBefore?.textContent || ''
            const match = textBefore.match(/@[\w\s-]*$/)
            
            if (match) {
              // Delete the @query text and insert mention
              const from = $from.pos - match[0].length
              return chain()
                .focus()
                .deleteRange({ from, to: $from.pos })
                .insertContent([
                  {
                    type: this.name,
                    attrs: attributes,
                  },
                  {
                    type: 'text',
                    text: ' ', // Add space after mention
                  },
                ])
                .run()
            }
          }

          // Just insert the mention at cursor
          return chain()
            .focus()
            .insertContent([
              {
                type: this.name,
                attrs: attributes,
              },
              {
                type: 'text',
                text: ' ', // Add space after mention
              },
            ])
            .run()
        },
    }
  },

  addKeyboardShortcuts() {
    return {
      // Delete the entire mention on backspace
      Backspace: () =>
        this.editor.commands.command(({ state, dispatch }) => {
          const { selection } = state
          const { $from, empty } = selection

          if (!empty) return false

          // Check if the node before cursor is a mention
          const nodeBefore = $from.nodeBefore
          if (nodeBefore?.type.name === this.name) {
            if (dispatch) {
              // Delete the entire mention node
              const tr = state.tr.delete(
                $from.pos - nodeBefore.nodeSize,
                $from.pos
              )
              dispatch(tr)
            }
            return true
          }

          return false
        }),
    }
  },
})

export default Mention
