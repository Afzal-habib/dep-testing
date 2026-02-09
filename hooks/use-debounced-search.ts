import { useState, useEffect, useCallback, useRef } from 'react';

interface UseDebounceSearchProps {
  onSearch: (searchTerm: string) => void;
  delay?: number;
}

interface UseDebounceSearchReturn {
  searchTerm: string;
  setSearchTerm: (term: string) => void;
  isSearching: boolean;
}

export function useDebounceSearch({ 
  onSearch, 
  delay = 500 
}: UseDebounceSearchProps): UseDebounceSearchReturn {
  const [searchTerm, setSearchTerm] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const onSearchRef = useRef(onSearch);

  // Update the ref when onSearch changes
  useEffect(() => {
    onSearchRef.current = onSearch;
  }, [onSearch]);

  useEffect(() => {
    if (searchTerm.length === 0) {
      onSearchRef.current('');
      return;
    }

    setIsSearching(true);
    const timeoutId = setTimeout(() => {
      onSearchRef.current(searchTerm);
      setIsSearching(false);
    }, delay);

    return () => {
      clearTimeout(timeoutId);
      setIsSearching(false);
    };
  }, [searchTerm, delay]); // Remove onSearch from dependency array

  return {
    searchTerm,
    setSearchTerm,
    isSearching,
  };
}