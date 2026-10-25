// Set LOCAL_TOKEN and REMOTE_TOKEN in your application; allow its exact origin
// in the backend ROOT/cors.conf. Do not embed live credentials in saved source.
async function gather(baseUrl, resourcePath, peer, localToken, remoteToken) {
  const response = await fetch(baseUrl + resourcePath, {
    headers: {
      Authorization: `Bearer ${localToken}`,
      'Client-Identifier': `pretend-to-be-client:${peer}`,
      'X-DocSec-Source-Authorization': `Bearer ${remoteToken}`
    }
  });
  // Trigger response has no information or JSON receipt.
  if (!response.ok) throw new Error(`Gather failed: HTTP ${response.status}`);
  return response.status;
}
async function readLocal(baseUrl, resourcePath, localToken) {
  const response = await fetch(baseUrl + resourcePath, {
    headers: {Authorization: `Bearer ${localToken}`}
  });
  if (!response.ok) throw new Error(`Read failed: HTTP ${response.status}`);
  return response.arrayBuffer();
}
