// Face presence check that runs entirely in the candidate's browser, using Google's
// MediaPipe face detector (BlazeFace short-range model). The detector's WebAssembly
// engine and the model are bundled with this site and served from our own server;
// no video or image is sent anywhere for this check — only the resulting warning.
import { FaceDetector } from '@mediapipe/tasks-vision';
import wasmLoaderPath from '@mediapipe/tasks-vision/vision_wasm_internal.js?url';
import wasmBinaryPath from '@mediapipe/tasks-vision/vision_wasm_internal.wasm?url';
import modelAssetPath from '../assets/models/blaze_face_short_range.tflite?url';

const MIN_SCORE = 0.5; // ignore weak detections (posters, reflections)

let loading = null;

/** Loads the detector once (GPU when available, otherwise CPU). Rejects if this device can't run it. */
export function loadFaceDetector() {
  if (!loading) {
    const make = (delegate) =>
      FaceDetector.createFromOptions(
        { wasmLoaderPath, wasmBinaryPath },
        { baseOptions: { modelAssetPath, delegate }, runningMode: 'VIDEO', minDetectionConfidence: MIN_SCORE },
      );
    loading = make('GPU').catch(() => make('CPU'));
    loading.catch(() => {
      loading = null; // allow a later retry
    });
  }
  return loading;
}

let lastTimestamp = 0;

/** Number of faces in the video's current frame, or null when no frame is ready yet. */
export function countFaces(detector, video) {
  if (!video || video.readyState < 2 || !video.videoWidth) return null;
  // MediaPipe needs strictly increasing timestamps across all calls.
  lastTimestamp = Math.max(performance.now(), lastTimestamp + 1);
  const result = detector.detectForVideo(video, lastTimestamp);
  return result.detections.filter((d) => (d.categories?.[0]?.score ?? 1) >= MIN_SCORE).length;
}
