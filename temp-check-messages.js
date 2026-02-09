// Use tsx to run this file: npx tsx temp-check-messages.js
import { prisma } from './lib/prisma.ts';

async function main() {
  const msgs = await prisma.messages.findMany({
    where: { channel_id: '1e795079-0c86-4d16-8dfc-57756fed00a3' },
    take: 10,
    orderBy: { created_at: 'desc' },
    select: { id: true, content: true }
  });
  
  console.log('=== Messages in channel ===');
  msgs.forEach((m, i) => {
    console.log(`\n--- Message ${i + 1} ---`);
    console.log('ID:', m.id);
    console.log('Content:', m.content);
  });
  
  // Also search for "helllo"
  const searchResults = await prisma.messages.findMany({
    where: {
      channel_id: '1e795079-0c86-4d16-8dfc-57756fed00a3',
      content: {
        contains: 'helllo',
        mode: 'insensitive'
      }
    },
    select: { id: true, content: true }
  });
  
  console.log('\n\n=== Search results for "helllo" ===');
  console.log('Found:', searchResults.length);
  searchResults.forEach(m => console.log(m.content));
  
  // Search for "hello" (2 l's)
  const searchResults2 = await prisma.messages.findMany({
    where: {
      channel_id: '1e795079-0c86-4d16-8dfc-57756fed00a3',
      content: {
        contains: 'hello',
        mode: 'insensitive'
      }
    },
    select: { id: true, content: true }
  });
  
  console.log('\n\n=== Search results for "hello" ===');
  console.log('Found:', searchResults2.length);
  searchResults2.forEach(m => console.log(m.content));
}

main().catch(console.error);
