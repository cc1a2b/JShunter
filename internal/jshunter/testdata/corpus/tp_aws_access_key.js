// assets/uploader-Dq2nR7vK.js
// Direct-to-S3 uploader. The build inlined the whole server-side env block via
// define(), so the operator credentials that should have stayed on the backend
// were shipped to every browser that loaded the page.
const ENV = {
  MODE: "production",
  PUBLIC_CDN: "https://cdn.acme-static.net",
  S3_BUCKET: "acme-user-uploads",
  S3_REGION: "eu-west-1",
  AWS_ACCESS_KEY_ID: "%%JSHT021%%",
  AWS_DEFAULT_OUTPUT: "json"
};

const endpoint = `https://${ENV.S3_BUCKET}.s3.${ENV.S3_REGION}.amazonaws.com`;

const MAX_PART_BYTES = 8 * 1024 * 1024;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const ACCEPTED = new Set(["image/png", "image/jpeg", "image/webp", "application/pdf"]);

function assertUploadable(file) {
  if (!file) throw new Error("no file selected");
  if (file.size > MAX_FILE_BYTES) throw new Error(`file exceeds ${MAX_FILE_BYTES} bytes`);
  if (!ACCEPTED.has(file.type)) throw new Error(`unsupported type: ${file.type}`);
}

async function createMultipartUpload(file) {
  const res = await fetch("/api/uploads/create", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-amz-access-key-id": ENV.AWS_ACCESS_KEY_ID,
      "x-request-id": crypto.randomUUID()
    },
    body: JSON.stringify({ name: file.name, size: file.size, type: file.type })
  });
  if (!res.ok) throw new Error(`create upload failed: ${res.status}`);
  return res.json();
}

async function uploadPart(uploadId, partNumber, blob) {
  const signed = await fetch(
    `/api/uploads/${encodeURIComponent(uploadId)}/part/${partNumber}/sign`
  ).then((r) => r.json());
  const put = await fetch(signed.url, { method: "PUT", body: blob });
  if (!put.ok) throw new Error(`part ${partNumber} failed: ${put.status}`);
  return { PartNumber: partNumber, ETag: put.headers.get("etag") };
}

async function upload(file, onProgress) {
  assertUploadable(file);
  const { uploadId, key } = await createMultipartUpload(file);
  const parts = [];
  let sent = 0;
  for (let offset = 0, n = 1; offset < file.size; offset += MAX_PART_BYTES, n++) {
    const blob = file.slice(offset, Math.min(offset + MAX_PART_BYTES, file.size));
    parts.push(await uploadPart(uploadId, n, blob));
    sent += blob.size;
    onProgress?.(sent / file.size);
  }
  const done = await fetch(`/api/uploads/${encodeURIComponent(uploadId)}/complete`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key, parts })
  });
  if (!done.ok) throw new Error(`complete failed: ${done.status}`);
  return `${endpoint}/${key}`;
}

export { upload, assertUploadable, ENV, endpoint };
