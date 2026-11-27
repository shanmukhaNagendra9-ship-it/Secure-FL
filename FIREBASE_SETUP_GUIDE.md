# Firebase Setup Guide — Spark-Compatible Hybrid Architecture (Windows & Linux)

This project uses **Firebase** as its managed cloud backend (Authentication, Cloud Firestore, Firebase Hosting, Security Rules, and optional Firebase Storage / Cloud Functions) paired with **local Python + Docker** for compute-intensive ML, Flower Federated Learning, Differential Privacy, and Explainable AI.

> **No dedicated cloud server or credit card is required.** All core services operate on the Firebase **Spark (free) plan** and/or the **Firebase Local Emulator Suite** with automatic local Python fallbacks.

---

## 1. Install Prerequisites (Windows PowerShell)

1. **Install Node.js LTS (20+)** from [nodejs.org](https://nodejs.org/) (needed for Firebase CLI and Rules testing).
2. **Install Firebase CLI**:
   ```powershell
   npm install -g firebase-tools
   firebase --version
   ```
3. **Install Java 17+** (required by Firebase Local Emulator Suite for Firestore & Storage emulators).
4. **Verify Python 3.11+ environment**:
   ```powershell
   C:\Users\shanm\Python311\python.exe -m pip install -r requirements.txt
   ```

---

## 2. Create & Configure Your Firebase Project

1. Go to the [Firebase Console](https://console.firebase.google.com/) and create a project (e.g., `securefl-prod`).
2. **Enable Authentication**:
   - Navigate to **Build -> Authentication -> Sign-in method**.
   - Enable **Email/Password**.
3. **Enable Cloud Firestore**:
   - Navigate to **Build -> Firestore Database -> Create database**.
   - Start in **production mode** (our `firestore.rules` enforces strict tenant isolation).
4. **Configure Firebase Hosting**:
   - Hosting is ready via `firebase.json` (`"public": "frontend"`).
5. **(Optional / Blaze) Storage & Cloud Functions**:
   - New Firebase Storage buckets and live Cloud Functions deployments require upgrading to Blaze (pay-as-you-go free tier).
   - **Staying on Spark?** Leave Cloud Functions undeployed and skip Storage provisioning: `backend/storage_service.py` automatically falls back to AES-256-GCM encrypted local artifacts (`artifacts/`) and `backend/response_engine.py` executes the exact alert/audit triggers locally.
6. **App Check (Recommended)**:
   - Register your Web App in **App Check** with **reCAPTCHA v3** and set `FIREBASE_APP_CHECK_ENFORCED=true` in `.env` when ready.

---

## 3. Configure Local Credentials (Never Commit Secrets!)

1. **Web App Config (Public)**:
   - Copy your Firebase Web SDK keys (`apiKey`, `authDomain`, `projectId`, `storageBucket`, `appId`) into `.env`.
2. **Service Account Key (Private Server Only)**:
   - In Firebase Console -> **Project Settings -> Service Accounts**, click **Generate new private key**.
   - Save as `serviceAccountKey.json` in the repo root (`.gitignore` already excludes it; **never** copy it into `frontend/`).
3. **Update `.firebaserc`**:
   ```json
   {
     "projects": {
       "default": "your-actual-firebase-project-id"
     }
   }
   ```
4. **Set Environment Variables in `.env`**:
   ```env
   FIREBASE_ENABLED=true
   FIREBASE_USE_EMULATOR=false
   FIREBASE_PROJECT_ID=your-actual-firebase-project-id
   JWT_SECRET_KEY=<64-char random hex>
   TENANT_MASTER_KEY=<64-char random hex>
   ```

---

## 4. Run Locally with Firebase Emulator Suite (Zero Cloud Cost)

```powershell
# Terminal 1: Start Firebase Emulators (Auth :9099, Firestore :8085, Storage :9199, Hosting :5000, Functions :5001)
firebase emulators:start

# Terminal 2: Start FastAPI Gateway connected to Emulators
$env:FIREBASE_ENABLED="true"
$env:FIREBASE_USE_EMULATOR="true"
.\start_backend.bat
```

### Run Automated Security Rules Unit Tests
```powershell
npm install --no-save @firebase/rules-unit-testing firebase
firebase emulators:exec --project securefl-rules-test --only firestore,storage "node tests/firebase_rules.test.mjs"
```

---

## 5. Deploy Hosting, Firestore Rules & Indexes to Firebase Cloud

```powershell
firebase login
firebase deploy --only firestore:rules,firestore:indexes,hosting
```
*(Include `,storage` and `,functions` only if your Firebase project has Storage/Blaze enabled.)*
