export default {
  async fetch(request) {
    const path = new URL(request.url).pathname.toLowerCase();
    const isCN = path === "/cn";
    const file = isCN ? "cn_top10_clash.yaml" : "au_top10_clash.yaml";
    const name = isCN ? "CN-Top10.yaml" : "AU-Top10.yaml";
    const url = "https://raw.githubusercontent.com/didixx0912/AU-top10/main/" + file;
    const res = await fetch(url, { cf: { cacheTtl: 600, cacheEverything: true } });
    if (!res.ok) {
      return new Response("Upstream error: " + res.status, { status: 502 });
    }
    return new Response(await res.text(), {
      headers: {
        "content-type": "text/yaml; charset=utf-8",
        "profile-update-interval": "12",
        "content-disposition": 'attachment; filename="' + name + '"',
        "cache-control": "public, max-age=600"
      }
    });
  }
};
