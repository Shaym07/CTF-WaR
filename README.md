# CTF War API - Render Deployment

## Quick Deploy to Render

### Option 1: Using Render Dashboard

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click **New** → **Web Service**
3. Connect your GitHub repo (or upload this folder)
4. Configure:
   - **Name**: ctf-war-api
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

5. Add Environment Variables:
   ```
   SUPABASE_URL=https://vfhilobaycsxwbjojgjc.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=<your_service_role_key>
   JWT_SECRET=c073386cb88b7d2fc6a4ad3ea0ab5718
   FLAG_PREFIXES=WOW
   ```

6. Click **Create Web Service**

### Option 2: Using render.yaml

1. Push this folder to GitHub
2. In Render, click **New** → **Blueprint**
3. Select your repo
4. Render will use `render.yaml` to configure everything

## After Deployment

Your API will be available at:
`https://ctf-war-api.onrender.com`

Update your frontend's API URL to point to your Render URL.

## Environment Variables

| Variable | Description |
|----------|-------------|
| SUPABASE_URL | Your Supabase project URL |
| SUPABASE_SERVICE_ROLE_KEY | Supabase service role key (from Settings → API) |
| JWT_SECRET | Secret key for JWT tokens |
| FLAG_PREFIXES | Allowed flag prefixes (comma-separated) |
| PORT | Server port (default: 3000) |

## API Endpoints

See the main documentation for all available endpoints.
