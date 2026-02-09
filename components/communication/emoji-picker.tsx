"use client"

import { useState, useRef, useEffect, useMemo, useCallback, memo } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"
import { Search, X, Smile } from "lucide-react"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

// ============================================
// Emoji Data (Single Source of Truth)
// ============================================

export const EMOJI_CATEGORIES = {
  "Frequently Used": [
    "👍", "❤️", "😂", "😮", "😢", "🔥", "👏", "🎉", "✅", "👀", "💯", "🙏",
    "😊", "💪", "🤔", "😍", "🥳", "👌", "🤝", "💡"
  ],
  "Smileys & People": [
    "😀", "😃", "😄", "😁", "😆", "😅", "🤣", "😂", "🙂", "🙃", "😉", "😊", "😇", "🥰", "😍", "🤩",
    "😘", "😗", "😚", "😙", "🥲", "😋", "😛", "😜", "🤪", "😝", "🤑", "🤗", "🤭", "🤫", "🤔", "🤐",
    "🤨", "😐", "😑", "😶", "😏", "😒", "🙄", "😬", "😮‍💨", "🤥", "😌", "😔", "😪", "🤤", "😴", "😷",
    "🤒", "🤕", "🤢", "🤮", "🤧", "🥵", "🥶", "🥴", "😵", "🤯", "🤠", "🥳", "🥸", "😎", "🤓", "🧐",
    "😕", "😟", "🙁", "☹️", "😮", "😯", "😲", "😳", "🥺", "😦", "😧", "😨", "😰", "😥", "😢", "😭",
    "😱", "😖", "😣", "😞", "😓", "😩", "😫", "🥱", "😤", "😡", "😠", "🤬", "😈", "👿", "💀", "☠️"
  ],
  "Gestures": [
    "👋", "🤚", "🖐️", "✋", "🖖", "👌", "🤌", "🤏", "✌️", "🤞", "🤟", "🤘", "🤙", "👈", "👉", "👆",
    "🖕", "👇", "☝️", "👍", "👎", "✊", "👊", "🤛", "🤜", "👏", "🙌", "👐", "🤲", "🤝", "🙏", "✍️",
    "💪", "🦾", "🦿", "🦵", "🦶", "👂", "🦻", "👃", "🧠", "🫀", "🫁", "🦷", "🦴", "👀", "👁️", "👅"
  ],
  "Hearts & Love": [
    "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔", "❣️", "💕", "💞", "💓", "💗", "💖",
    "💘", "💝", "💟", "♥️", "❤️‍🔥", "❤️‍🩹", "🫀", "💋", "💌", "💐", "🌹", "🥀", "💍", "💎", "👫", "💏"
  ],
  "Nature & Animals": [
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐻‍❄️", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵",
    "🐔", "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇", "🐺", "🐗", "🐴", "🦄", "🐝", "🪱", "🐛", "🦋",
    "🐌", "🐞", "🐜", "🦟", "🦗", "🕷️", "🦂", "🐢", "🐍", "🦎", "🦖", "🦕", "🐙", "🦑", "🦐", "🦞",
    "🌸", "💮", "🏵️", "🌹", "🥀", "🌺", "🌻", "🌼", "🌷", "🌱", "🪴", "🌲", "🌳", "🌴", "🌵", "🌾",
    "🌿", "☘️", "🍀", "🍁", "🍂", "🍃", "🌍", "🌎", "🌏", "🌑", "🌒", "🌓", "🌔", "🌕", "🌙", "⭐"
  ],
  "Food & Drink": [
    "🍎", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐", "🍈", "🍒", "🍑", "🥭", "🍍", "🥥", "🥝", "🍅",
    "🍆", "🥑", "🥦", "🥬", "🥒", "🌶️", "🫑", "🌽", "🥕", "🧄", "🧅", "🥔", "🍠", "🥐", "🥯", "🍞",
    "🥖", "🥨", "🧀", "🥚", "🍳", "🧈", "🥞", "🧇", "🥓", "🥩", "🍗", "🍖", "🌭", "🍔", "🍟", "🍕",
    "🫓", "🥪", "🥙", "🧆", "🌮", "🌯", "🫔", "🥗", "🥘", "🫕", "🍝", "🍜", "🍲", "🍛", "🍣", "🍱",
    "🥟", "🦪", "🍤", "🍙", "🍚", "🍘", "🍥", "🥠", "🥮", "🍢", "🍡", "🍧", "🍨", "🍦", "🥧", "🧁",
    "🍰", "🎂", "🍮", "🍭", "🍬", "🍫", "🍿", "🍩", "🍪", "☕", "🍵", "🧃", "🥤", "🧋", "🍺", "🍻"
  ],
  "Activities": [
    "⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉", "🥏", "🎱", "🪀", "🏓", "🏸", "🏒", "🏑", "🥍",
    "🏏", "🪃", "🥅", "⛳", "🪁", "🏹", "🎣", "🤿", "🥊", "🥋", "🎽", "🛹", "🛼", "🛷", "⛸️", "🥌",
    "🎿", "⛷️", "🏂", "🪂", "🏋️", "🤼", "🤸", "🤺", "⛹️", "🤾", "🏌️", "🏇", "🧘", "🏄", "🏊", "🤽",
    "🚣", "🧗", "🚵", "🚴", "🏆", "🥇", "🥈", "🥉", "🏅", "🎖️", "🏵️", "🎗️", "🎫", "🎟️", "🎪", "🎭",
    "🎨", "🎬", "🎤", "🎧", "🎼", "🎹", "🥁", "🪘", "🎷", "🎺", "🪗", "🎸", "🪕", "🎻", "🎲", "♟️",
    "🎯", "🎳", "🎮", "🎰", "🧩"
  ],
  "Objects": [
    "⌚", "📱", "📲", "💻", "⌨️", "🖥️", "🖨️", "🖱️", "🖲️", "🕹️", "🗜️", "💽", "💾", "💿", "📀", "📼",
    "📷", "📸", "📹", "🎥", "📽️", "🎞️", "📞", "☎️", "📟", "📠", "📺", "📻", "🎙️", "🎚️", "🎛️", "🧭",
    "⏱️", "⏲️", "⏰", "🕰️", "⌛", "⏳", "📡", "🔋", "🔌", "💡", "🔦", "🕯️", "🪔", "🧯", "🛢️", "💸",
    "💵", "💴", "💶", "💷", "🪙", "💰", "💳", "💎", "⚖️", "🪜", "🧰", "🪛", "🔧", "🔨", "⚒️", "🛠️",
    "⛏️", "🪚", "🔩", "⚙️", "🪤", "🧱", "⛓️", "🧲", "🔫", "💣", "🧨", "🪓", "🔪", "🗡️", "⚔️", "🛡️",
    "📧", "📨", "📩", "📤", "📥", "📦", "📫", "📪", "📬", "📭", "📮", "🗳️", "✏️", "✒️", "🖋️", "🖊️",
    "📝", "💼", "📁", "📂", "🗂️", "📅", "📆", "🗒️", "🗓️", "📇", "📈", "📉", "📊", "📋", "📌", "📍"
  ],
  "Symbols": [
    "🔥", "✨", "⭐", "🌟", "💫", "💥", "💢", "💦", "💨", "🎉", "🎊", "🎈", "🎁", "🏆", "🥇", "🥈",
    "❌", "⭕", "🛑", "⛔", "📛", "🚫", "💯", "💢", "♨️", "🚷", "🚯", "🚳", "🚱", "🔞", "📵", "🚭",
    "❗", "❕", "❓", "❔", "‼️", "⁉️", "🔅", "🔆", "〽️", "⚠️", "🚸", "🔱", "⚜️", "🔰", "♻️", "✅",
    "🈯", "💹", "❇️", "✳️", "❎", "🌐", "💠", "Ⓜ️", "🌀", "💤", "🏧", "🚾", "♿", "🅿️", "🛗", "🈳"
  ],
  "Flags": [
    "🏳️", "🏴", "🏁", "🚩", "🏳️‍🌈", "🏳️‍⚧️", "🏴‍☠️", "🇦🇫", "🇦🇱", "🇩🇿", "🇦🇸", "🇦🇩", "🇦🇴", "🇦🇮", "🇦🇶", "🇦🇬",
    "🇦🇷", "🇦🇲", "🇦🇼", "🇦🇺", "🇦🇹", "🇦🇿", "🇧🇸", "🇧🇭", "🇧🇩", "🇧🇧", "🇧🇾", "🇧🇪", "🇧🇿", "🇧🇯", "🇧🇲", "🇧🇹",
    "🇧🇴", "🇧🇦", "🇧🇼", "🇧🇷", "🇮🇴", "🇻🇬", "🇧🇳", "🇧🇬", "🇧🇫", "🇧🇮", "🇰🇭", "🇨🇲", "🇨🇦", "🇮🇨", "🇨🇻", "🇧🇶",
    "🇰🇾", "🇨🇫", "🇹🇩", "🇨🇱", "🇨🇳", "🇨🇽", "🇨🇨", "🇨🇴", "🇰🇲", "🇨🇬", "🇨🇩", "🇨🇰", "🇨🇷", "🇭🇷", "🇨🇺", "🇨🇼"
  ]
}

// Quick reaction emojis (for message reactions)
export const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🔥", "👏", "🎉"]

// Category icons for tabs
const CATEGORY_ICONS: Record<string, string> = {
  "Frequently Used": "⏰",
  "Smileys & People": "😊",
  "Gestures": "👋",
  "Hearts & Love": "❤️",
  "Nature & Animals": "🐶",
  "Food & Drink": "🍕",
  "Activities": "⚽",
  "Objects": "💡",
  "Symbols": "✨",
  "Flags": "🏳️"
}

// ============================================
// Shared Emoji Grid Component
// ============================================

interface EmojiGridProps {
  emojis: string[]
  onSelect: (emoji: string) => void
  columns?: number
  size?: "sm" | "md" | "lg"
}

const EmojiGrid = memo(function EmojiGrid({
  emojis,
  onSelect,
  columns = 8,
  size = "md"
}: EmojiGridProps) {
  const sizeClasses = {
    sm: "h-6 w-6 text-sm",
    md: "h-8 w-8 text-lg",
    lg: "h-10 w-10 text-xl"
  }

  return (
    <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
      {emojis.map((emoji, idx) => (
        <Button
          key={`${emoji}-${idx}`}
          variant="ghost"
          size="sm"
          className={cn(
            "p-0 hover:bg-muted hover:scale-110 transition-transform rounded",
            sizeClasses[size]
          )}
          onClick={() => onSelect(emoji)}
        >
          {emoji}
        </Button>
      ))}
    </div>
  )
})

// ============================================
// Main Emoji Picker Component (Popover-based)
// ============================================

interface EmojiPickerProps {
  onSelect: (emoji: string) => void
  onClose?: () => void
  className?: string
  triggerClassName?: string
  triggerIcon?: React.ReactNode
  showTrigger?: boolean
  showQuickAccess?: boolean
  align?: "start" | "center" | "end"
  side?: "top" | "right" | "bottom" | "left"
  disabled?: boolean
}

export const EmojiPicker = memo(function EmojiPicker({
  onSelect,
  onClose,
  className,
  triggerClassName,
  triggerIcon,
  showTrigger = true,
  showQuickAccess = true,
  align = "start",
  side = "top",
  disabled = false
}: EmojiPickerProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [activeCategory, setActiveCategory] = useState("Frequently Used")
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Filter emojis based on search
  const filteredEmojis = useMemo(() => {
    if (!searchQuery.trim()) return null

    const allEmojis: string[] = []
    Object.values(EMOJI_CATEGORIES).forEach(emojis => {
      emojis.forEach(emoji => {
        if (!allEmojis.includes(emoji)) {
          allEmojis.push(emoji)
        }
      })
    })

    // Return all emojis when searching (in production, use emoji keywords for real search)
    return allEmojis.slice(0, 60)
  }, [searchQuery])

  const handleSelect = useCallback((emoji: string) => {
    onSelect(emoji)
    setIsOpen(false)
    setSearchQuery("")
    onClose?.()
  }, [onSelect, onClose])

  const handleOpenChange = useCallback((open: boolean) => {
    setIsOpen(open)
    if (!open) {
      setSearchQuery("")
      onClose?.()
    }
  }, [onClose])

  // Focus search on open
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        searchInputRef.current?.focus()
      }, 100)
    }
  }, [isOpen])

  const categories = Object.keys(EMOJI_CATEGORIES)

  const pickerContent = (
    <div className="w-80">
      {/* Quick access bar */}
      {showQuickAccess && (
        <div className="flex items-center gap-1 p-2 border-b">
          {QUICK_REACTIONS.map(emoji => (
            <Button
              key={emoji}
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-lg hover:bg-muted hover:scale-110 transition-transform"
              onClick={() => handleSelect(emoji)}
            >
              {emoji}
            </Button>
          ))}
        </div>
      )}

      {/* Search */}
      <div className="p-2 border-b">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            ref={searchInputRef}
            placeholder="Search emoji..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 pl-8 pr-8 text-sm"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Category tabs */}
      {!searchQuery && (
        <TooltipProvider>
          <div className="flex items-center gap-0.5 p-1 border-b overflow-x-auto scrollbar-hide">
            {categories.map(category => (
              <Tooltip key={category}>
                <TooltipTrigger asChild>
                  <Button
                    variant={activeCategory === category ? "secondary" : "ghost"}
                    size="sm"
                    className="h-7 w-7 p-0 text-base flex-shrink-0"
                    onClick={() => setActiveCategory(category)}
                  >
                    {CATEGORY_ICONS[category] || "📁"}
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="text-xs">
                  {category}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
        </TooltipProvider>
      )}

      {/* Emoji grid */}
      <ScrollArea className="h-52">
        <div className="p-2">
          {searchQuery ? (
            filteredEmojis && filteredEmojis.length > 0 ? (
              <EmojiGrid emojis={filteredEmojis} onSelect={handleSelect} />
            ) : (
              <p className="text-center text-sm text-muted-foreground py-8">
                No emojis found
              </p>
            )
          ) : (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2 px-1">
                {activeCategory}
              </p>
              <EmojiGrid
                emojis={EMOJI_CATEGORIES[activeCategory as keyof typeof EMOJI_CATEGORIES] || []}
                onSelect={handleSelect}
              />
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  )

  if (!showTrigger) {
    return <div className={className}>{pickerContent}</div>
  }

  return (
    <Popover open={isOpen} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn("h-8 w-8 p-0 hover:bg-muted", triggerClassName)}
          disabled={disabled}
        >
          {triggerIcon || <Smile className="h-4 w-4 text-muted-foreground" />}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className={cn("w-80 p-0", className)}
        align={align}
        side={side}
        sideOffset={5}
      >
        {pickerContent}
      </PopoverContent>
    </Popover>
  )
})

// ============================================
// Inline Emoji Picker (Non-popover, for embedding)
// ============================================

interface InlineEmojiPickerProps {
  onSelect: (emoji: string) => void
  onClose: () => void
  className?: string
}

export function InlineEmojiPicker({ onSelect, onClose, className }: InlineEmojiPickerProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [activeCategory, setActiveCategory] = useState("Frequently Used")
  const pickerRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Focus search on mount
  useEffect(() => {
    searchInputRef.current?.focus()
  }, [])

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [onClose])

  // Close on escape
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("keydown", handleEscape)
    return () => document.removeEventListener("keydown", handleEscape)
  }, [onClose])

  // Filter emojis based on search
  const filteredEmojis = useMemo(() => {
    if (!searchQuery.trim()) return null

    const allEmojis: string[] = []
    Object.values(EMOJI_CATEGORIES).forEach(emojis => {
      emojis.forEach(emoji => {
        if (!allEmojis.includes(emoji)) {
          allEmojis.push(emoji)
        }
      })
    })

    return allEmojis.slice(0, 50)
  }, [searchQuery])

  const handleEmojiClick = (emoji: string) => {
    onSelect(emoji)
    onClose()
  }

  const categories = Object.keys(EMOJI_CATEGORIES)

  return (
    <div
      ref={pickerRef}
      className={cn(
        "absolute bottom-full mb-2 w-80 bg-card border rounded-lg shadow-lg z-50",
        className
      )}
    >
      {/* Header with search */}
      <div className="p-2 border-b">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            ref={searchInputRef}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search emoji..."
            className="pl-8 pr-8 h-8 text-sm"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Category tabs (only show when not searching) */}
      {!searchQuery && (
        <div className="flex items-center gap-1 p-1 border-b overflow-x-auto scrollbar-hide">
          {categories.map((category) => (
            <button
              key={category}
              onClick={() => setActiveCategory(category)}
              className={cn(
                "px-2 py-1 text-xs rounded whitespace-nowrap transition-colors",
                activeCategory === category
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted"
              )}
            >
              {category.split(" ")[0]}
            </button>
          ))}
        </div>
      )}

      {/* Emoji grid */}
      <ScrollArea className="h-64 p-2">
        {searchQuery ? (
          <div>
            {filteredEmojis && filteredEmojis.length > 0 ? (
              <div className="grid grid-cols-8 gap-1">
                {filteredEmojis.map((emoji, idx) => (
                  <button
                    key={`search-${idx}`}
                    onClick={() => handleEmojiClick(emoji)}
                    className="p-1.5 text-xl hover:bg-muted rounded transition-colors"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-center text-sm text-muted-foreground py-4">
                No emojis found
              </p>
            )}
          </div>
        ) : (
          <div>
            {/* Frequently used */}
            <div className="mb-3">
              <p className="text-xs font-medium text-muted-foreground mb-1 px-1">
                Frequently Used
              </p>
              <div className="grid grid-cols-8 gap-1">
                {EMOJI_CATEGORIES["Frequently Used"].slice(0, 16).map((emoji, idx) => (
                  <button
                    key={`freq-${idx}`}
                    onClick={() => handleEmojiClick(emoji)}
                    className="p-1.5 text-xl hover:bg-muted rounded transition-colors"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            </div>

            {/* Active category */}
            {activeCategory !== "Frequently Used" && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1 px-1">
                  {activeCategory}
                </p>
                <div className="grid grid-cols-8 gap-1">
                  {EMOJI_CATEGORIES[activeCategory as keyof typeof EMOJI_CATEGORIES]?.map((emoji, idx) => (
                    <button
                      key={`${activeCategory}-${idx}`}
                      onClick={() => handleEmojiClick(emoji)}
                      className="p-1.5 text-xl hover:bg-muted rounded transition-colors"
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </ScrollArea>
    </div>
  )
}

// ============================================
// Quick Reaction Bar (for message hover)
// ============================================

interface QuickReactionBarProps {
  onSelect: (emoji: string) => void
  className?: string
}

export const QuickReactionBar = memo(function QuickReactionBar({
  onSelect,
  className
}: QuickReactionBarProps) {
  return (
    <div className={cn(
      "flex items-center gap-0.5 bg-background/95 backdrop-blur-sm border rounded-full px-0.5 py-0.5 shadow-sm",
      className
    )}>
      {QUICK_REACTIONS.slice(0, 6).map(emoji => (
        <Button
          key={emoji}
          variant="ghost"
          size="sm"
          className="h-5 w-5 p-0 text-xs hover:bg-muted hover:scale-110 transition-transform rounded-full"
          onClick={() => onSelect(emoji)}
        >
          {emoji}
        </Button>
      ))}
      <EmojiPicker
        onSelect={onSelect}
        showQuickAccess={false}
        triggerClassName="h-5 w-5 rounded-full"
        side="top"
        align="end"
      />
    </div>
  )
})

// ============================================
// Message Reactions Display
// ============================================

interface IGroupedReaction {
  emoji: string
  count: number
  users: { id?: string; mongo_user_id: string; name?: string }[]
  hasCurrentUserReacted: boolean
}

interface MessageReactionsProps {
  reactions: IGroupedReaction[]
  onReactionClick: (emoji: string) => void
  className?: string
  currentUserId?: string
}

export const MessageReactions = memo(function MessageReactions({
  reactions,
  onReactionClick,
  className,
  currentUserId
}: MessageReactionsProps) {
  if (!reactions || reactions.length === 0) return null

  return (
    <TooltipProvider>
      <div className={cn("flex flex-wrap gap-0.5 mt-0.5", className)}>
        {reactions.map((reaction, index) => {
          // Comprehensive emoji validation and fallback
          let displayEmoji = reaction.emoji

          // Check if emoji field contains UUID or invalid data
          if (!displayEmoji ||
            displayEmoji.length > 10 ||
            displayEmoji.includes('-') ||
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(displayEmoji)) {
            displayEmoji = '👍' // Fallback to default emoji
          }

          const userNames = reaction.users
            .slice(0, 10)
            .map(u => u.name || 'Someone')
            .join(', ')

          const tooltipText = reaction.users.length > 10
            ? `${userNames} and ${reaction.users.length - 10} more reacted with ${displayEmoji}`
            : `${userNames} reacted with ${displayEmoji}`

          return (
            <Tooltip key={`reaction-${index}-${displayEmoji}-${reaction.count}`}>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className={cn(
                    "h-5 px-1 py-0 text-[10px] gap-0.5 rounded-full border transition-all",
                    reaction.hasCurrentUserReacted
                      ? "bg-primary/10 border-primary/30 hover:bg-primary/20 text-primary"
                      : "bg-muted/40 hover:bg-muted border-muted"
                  )}
                  onClick={() => onReactionClick(displayEmoji)}
                >
                  <span className="text-xs leading-none select-none">{displayEmoji}</span>
                  <span className={cn(
                    "font-medium text-[10px]",
                    reaction.hasCurrentUserReacted ? "text-primary" : "text-muted-foreground"
                  )}>
                    {reaction.count}
                  </span>
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                <div className="text-[10px]">
                  {tooltipText}
                </div>
              </TooltipContent>
            </Tooltip>
          )
        })}

        {/* Add reaction button - WhatsApp style */}
        <EmojiPicker
          onSelect={onReactionClick}
          showQuickAccess={false}
          triggerClassName="h-5 w-5 rounded-full border bg-muted/30 hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
          side="top"
        />
      </div>
    </TooltipProvider>
  )
})

// Default export
export default EmojiPicker
