# ThreatTrail Frontend 🛡️💻

The user-facing Single Page Application (SPA) for **ThreatTrail**, built with React 19 and Vite.

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Configuration (Optional)
If running the backend on a non-default host or port, configure `.env`:
```bash
# Default targets local FastAPI backend on port 5050
VITE_API_URL=http://localhost:5050/api
```

### 3. Start Development Server
```bash
npm run dev
```
The app will be available at [http://localhost:5173](http://localhost:5173).

## Available Scripts

- `npm run dev`: Launch the Vite dev server with hot module replacement (HMR).
- `npm run build`: Compile and minify production bundle into `dist/`.
- `npm run preview`: Locally preview the production build.
- `npm run lint`: Run ESLint across the codebase.

## Tech Stack
- **Framework:** React 19
- **Build Tool:** Vite 8
- **Routing:** React Router 7
- **HTTP Client:** Axios (with automatic Bearer token injection)
- **Icons:** Lucide React
- **Styles:** Custom SOC dashboard theme in `src/App.css`

For full project documentation, see the root [README.md](../README.md).
