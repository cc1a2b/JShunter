// assets/firebase-init-Bq7nX2vT.js
// Firebase Web SDK v12 modular bootstrap. Every value in firebaseConfig is
// public by design: it ships to every browser that loads the app and access
// is controlled by Security Rules and App Check, not by secrecy.
import { initializeApp } from "firebase/app";
import { getAuth, onAuthStateChanged } from "firebase/auth";
import { getFirestore, doc, getDoc } from "firebase/firestore";
import { getMessaging, getToken } from "firebase/messaging";
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "firebase/app-check";
import { getAnalytics, logEvent } from "firebase/analytics";

const firebaseConfig = {
  apiKey: "%%JSHT002%%",
  authDomain: "acme-storefront.firebaseapp.com",
  databaseURL: "https://acme-storefront-default-rtdb.firebaseio.com",
  projectId: "acme-storefront",
  storageBucket: "acme-storefront.appspot.com",
  messagingSenderId: "918273645012",
  appId: "1:918273645012:web:26148512b82d0dee17b97d44",
  measurementId: "G-7QK2M4XVD1"
};

const emulatorConfig = {
  auth: "http://127.0.0.1:9099",
  firestore: "127.0.0.1:8080",
  storage: "127.0.0.1:9199"
};

const app = initializeApp(firebaseConfig);

// App Check site key is also public — it is the reCAPTCHA Enterprise key that
// the browser needs in order to mint an attestation token.
const appCheck = initializeAppCheck(app, {
  provider: new ReCaptchaEnterpriseProvider("6LfAcmeStorefrontPublicSiteKey01xQ9"),
  isTokenAutoRefreshEnabled: true
});

const auth = getAuth(app);
const db = getFirestore(app);
const analytics = typeof window !== "undefined" ? getAnalytics(app) : null;

// VAPID public key for Web Push. The matching private key stays on the server.
const VAPID_PUBLIC_KEY =
  "BJ9pQ2vL4wZnYt6BsAdF3gHj5sCe0uTb1oPqNrMzXkR7yWvU2aTd8HgKmLpQnBc4EfGh6JkLmNpQrStUvWxYz01";

async function requestPushToken() {
  const messaging = getMessaging(app);
  try {
    return await getToken(messaging, { vapidKey: VAPID_PUBLIC_KEY });
  } catch (err) {
    console.warn("[fcm] token request rejected", err && err.code);
    return null;
  }
}

function watchSession(onUser) {
  return onAuthStateChanged(auth, async (user) => {
    if (!user) return onUser(null);
    const snap = await getDoc(doc(db, "profiles", user.uid));
    onUser({
      uid: user.uid,
      email: user.email,
      tier: snap.exists() ? snap.data().tier : "free",
      projectId: firebaseConfig.projectId
    });
  });
}

function track(name, params) {
  if (!analytics) return;
  logEvent(analytics, name, { ...params, measurementId: firebaseConfig.measurementId });
}

export {
  app,
  auth,
  db,
  appCheck,
  firebaseConfig,
  emulatorConfig,
  requestPushToken,
  watchSession,
  track,
  VAPID_PUBLIC_KEY
};
