npm run migrate    -- Run all migrations
npm run seed - Run all seeders
npm run reset - Reset database (drop all + migrate + seed)
npm run setup - Complete setup (migrate + seed)
npm run migrate:new - Migrate only new models
npm run seed:single [ModelName] - Seed a specific model





## Prisma related db commands 
Development Workflow:

### Make schema changes in schema.prisma
1) Run to create migration
npx prisma migrate dev
# or npm run db:migrate

2) Run to update client
npx prisma generate
# or npm run db:generate

3) Run to populate data
npm run db:seed 
 
### Production Deployment:

4) Run to apply migrations
npx prisma migrate deploy 
5) Run to ensure client is up-to-date
npm run db:generate 

### Troubleshooting:

6) Use to inspect data(Opens a web-based database browser to view and edit data directly.)
npx prisma studio 

7) Use to start fresh
npx prisma migrate reset --force 

###  Pushes schema changes directly to the database without creating migration files (good for quick prototyping).

npx prisma db push
# or npm run db:push

### Schema Validation (Validates your schema.prisma file for syntax and consistency errors.)

npx prisma validate