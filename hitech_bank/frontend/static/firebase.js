/**
 * HiTech Bank — Firebase Phone Auth (Web SDK)
 *
 * Config matches `Firebase otp generator.txt` (project otp-generator-5c003).
 * Backend verifies ID tokens with `serviceAccountKey.json` via Firebase Admin (app.py / auth.py).
 *
 * IMPORTANT — why you may not receive an SMS:
 * Numbers listed under Firebase Console → Authentication → Settings →
 * "Phone numbers for testing" never get a real SMS. Firebase expects you to
 * enter the fixed 6-digit code shown next to that number in the console.
 * For real SMS, use a number that is NOT on the test list, and ensure this
 * site's domain (e.g. localhost) is under Authentication → Settings →
 * Authorized domains.
 */
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import {
  getAuth,
  RecaptchaVerifier,
  signInWithPhoneNumber,
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyAw2bl9UzwN4yflbtpuwF6OuD5mm_9wt8I",
  authDomain: "otp-generator-5c003.firebaseapp.com",
  projectId: "otp-generator-5c003",
  storageBucket: "otp-generator-5c003.firebasestorage.app",
  messagingSenderId: "5808289509",
  appId: "1:5808289509:web:b017dad322f9936aec460c",
  measurementId: "G-PK16EVT00N",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

let recaptchaVerifier = null;

/**
 * @param {string} raw
 * @returns {string} E.164-style string (default India +91 if no country code)
 */
function normalizePhone(raw) {
  if (!raw || typeof raw !== "string") return "";
  let p = raw.trim().replace(/\s+/g, "");
  if (!p.startsWith("+")) {
    const digits = p.replace(/\D/g, "");
    p = "+91" + digits;
  }
  return p;
}

function getRecaptchaContainer() {
  const el = document.getElementById("recaptcha-container");
  if (!el) {
    throw new Error(
      'Missing #recaptcha-container in the page (required for Firebase Phone Auth).'
    );
  }
  return el;
}

/**
 * Start phone sign-in; returns a confirmation result — call confirmPhoneOtp next.
 * @param {string} phoneE164
 */
async function sendPhoneOtp(phoneE164) {
  getRecaptchaContainer();
  if (recaptchaVerifier) {
    try {
      recaptchaVerifier.clear();
    } catch (_) {
      /* ignore */
    }
    recaptchaVerifier = null;
  }
  recaptchaVerifier = new RecaptchaVerifier(auth, "recaptcha-container", {
    size: "invisible",
    callback: () => {},
  });
  return signInWithPhoneNumber(auth, phoneE164, recaptchaVerifier);
}

/**
 * @param {*} confirmationResult — object returned from sendPhoneOtp (Firebase ConfirmationResult)
 * @param {string} otpCode
 * @returns {Promise<string>} Firebase ID token (send to backend as firebase_token)
 */
async function confirmPhoneOtp(confirmationResult, otpCode) {
  const code = String(otpCode || "").trim();
  const cred = await confirmationResult.confirm(code);
  return cred.user.getIdToken();
}

function resetRecaptcha() {
  if (recaptchaVerifier) {
    try {
      recaptchaVerifier.clear();
    } catch (_) {
      /* ignore */
    }
    recaptchaVerifier = null;
  }
}

window.HiTechFirebase = {
  auth,
  normalizePhone,
  sendPhoneOtp,
  confirmPhoneOtp,
  resetRecaptcha,
};
