# Evasion and limitations

* Sub-threshold brute force (fewer than 5 failures / 5 minutes) is not
  flagged by the rule detector; the ML ensemble may still score the
  session.
* Timestomping that never emits 4616 is invisible to the anti-forensic
  module. RecordID gaps catch selective deletion only when the remaining
  stream is still present.
* Script-block logging (4104) can itself be cleared; we detect 1102/104
  but cannot recover the deleted script text.
* Geolocation uses a built-in table, not a live GeoIP database. Unknown
  public IPs will not trip impossible-travel.
* Live Windows subscription requires pywin32 and Administrator rights.
* Digital signatures and RFC 3161 tokens are integrity evidence, not
  legal chain-of-custody under any specific jurisdiction.
