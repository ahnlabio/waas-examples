
const WAAS_BASE_URL:string = "https://dev-api.waas.myabcwallet.com"
function getBaseURL(): string {
    const waas_base_url: string = process.env["WAAS_BASE_URL"] == "" ? WAAS_BASE_URL : process.env["WAAS_BASE_URL"]

    return waas_base_url
}