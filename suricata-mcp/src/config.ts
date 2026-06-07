export interface SuricataConfig {
  evePath: string;
  eveArchiveDir: string;
  maxResults: number;
  zeekLogsDir: string | null;
}

export function getConfig(): SuricataConfig {
  return {
    evePath:
      process.env.SURICATA_EVE_LOG ??
      process.env.SURICATA_EVE_PATH ??
      process.env.EVE_JSON_PATH ??
      "/var/log/suricata/eve.json",
    eveArchiveDir: process.env.SURICATA_EVE_ARCHIVE ?? "/var/log/suricata/",
    maxResults: parseInt(process.env.SURICATA_MAX_RESULTS ?? "1000", 10),
    zeekLogsDir: process.env.ZEEK_LOGS_DIR ?? null,
  };
}
