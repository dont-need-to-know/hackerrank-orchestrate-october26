a


def parse_state(record, text, prefix):
    raw = (json.dumps(record, default=str, ensure_ascii=False) if record else "") + " " + (text or "")
    low = raw.casefold()
    absent = False
    if record:
        for k in ("status_code", "http_status", "status", "record_status", "state", "result", "lookup_status"):
            val = norm(record.get(k))
            if val in {"404", "absent", "deleted", "purged", "not_found", "not found", "missing", "not_found"}: absent = True
        if prefix == "tombstone": absent = False
    else:
        absent = bool(re.search(r"\b(404|not_found|not found|absent|purged|record_absent|no record|missing|rows=0)\b", low))
    enabled = None
    for key in ("enabled", "is_enabled", "active", "is_active", "flow_enabled"):
        if record and key in record and record[key] is not None:
            v = norm(record[key]); enabled = v in {"true", "1", "yes", "enabled", "active"}
            break
    restore = None
    for key in ("restore_allowed", "restore_enabled", "can_restore", "restore_access"):
        if record and key in record and record[key] is not None:
            v = norm(record[key]); restore = v in {"true", "1", "yes", "allowed", "enabled", "active"}
            break
    if re.search(r"\b(disabled|inactive|flow_off|flow_disabled)\b", low): enabled = False
    if re.search(r"\b(restore_blocked|block_restore|restore_access=blocked|cannot_restore)\b", low): restore = False
    if re.search(r"\b(restore_enabled|restore_allowed=true|can_restore=true|restore_access=allowed|eligible=true)\b", low) and not re.search(r"deletion_block=true", low): restore = True
    if re.search(r"can still be restored|restore access.*allowed|restore_access=allowed", low): restore = True
    if re.search(r"\b(flow_enabled|enabled=true|active=true)\b", low) and prefix == "data_flow": enabled = True
    if not record and re.search(r"\b(404|not_found|not found|absent|deleted|purged|record_absent|no record|missing|rows=0)\b", low): absent = True
    return {"absent": absent, "enabled": enabled, "restore": restore, "raw": raw, "low": low}


def load_activity_links(activities, aliases, uid, cutoff, requested_at=None):
    links = {}
    for a in activities:
        if not at_or_before(a.get("event_time"), cutoff): continue
        if requested_at and dt(a.get("event_time")) and dt(a.get("event_time")) < requested_at: continue
        if norm(a.get("event_type")) != "link_resource_identity": continue
        details = str(a.get("details") or "")
        res = str(a.get("resource_id") or "").strip()
        if not res: continue
        if exact_text_link(details, aliases):
            links[res] = {"activity_id": a.get("activity_id", ""), "details": details,
                          "exclusive": bool(re.search(r"belongs only to .*?(?:;|,| and user_|$)|no other subject", details, re.I))}
        elif uid and re.search(r"\b" + re.escape(uid) + r"\b", details, re.I):
            links[res] = {"activity_id": a.get("activity_id", ""), "details": details,
                          "exclusive": bool(re.search(r"belongs only to .*?(?:;|,| and user_|$)|no other subject", details, re.I))}
    return links


def build_observations(evidence, activities, aliases, uid, cutoff, requested_at=None):
    links = load_activity_links(activities, aliases, uid, cutoff, requested_at)
    obs = []
    for e in evidence:
        meta = e["meta"]
        cap = dt(meta.get("captured_at"))
        if cap is None: continue
        late_capture = cap > cutoff
        # A late-captured log may expose a pre-cutoff event timestamp, but is never citable.
        # Structured snapshots without record-level timestamps are not used past the cutoff.
        pre_request_snapshot = any(k in meta.get("file_path", "").lower() for k in ("service_resource_export", "customer_data_snapshot_bundle"))
        if requested_at and cap < requested_at and not late_capture and not pre_request_snapshot: continue
        eid = meta["file_id"] if not late_capture else ""
        for record, context in e["records"]:
            res = str(record.get("resource_id") or record.get("account_id") or context.get("resource_id") or "").strip()
            if not res:
                # Do not treat arbitrary IDs as resources; only explicit resource_id/account_id fields.
                continue
            if not RESOURCE_RE.fullmatch(res) or res.casefold().endswith(("_service", "_platform")): continue
            if not record_identity_match(record, aliases) and res not in links: continue
            rec_time = next((record.get(k) or context.get(k) for k in
                             ("event_time", "observed_at", "snapshot_at", "captured_at", "updated_at", "indexed_at", "created_at", "timestamp")
                             if record.get(k) or context.get(k)), None)
            if late_capture and (not rec_time or not at_or_before(rec_time, cutoff)): continue
            if rec_time and not at_or_before(rec_time, cutoff): continue
            if requested_at and rec_time and dt(rec_time) and dt(rec_time) < requested_at and not res.startswith(("audit_record_", "legal_hold_")) and not pre_request_snapshot:
                continue
            prefix = resource_prefix(res)
            rec_context = dict(context)
            rec_context.setdefault("data_store", record.get("data_store") or record.get("system_id"))
            rec_context.setdefault("collection", record.get("collection"))
            category = record_category(record, rec_context, res)
            state = parse_state(record, "", prefix)
            obs.append({"resource":res,"prefix":prefix,"system":get_resource_system(res,rec_context),"category":category,
                        "record":record,"text":"","state":state,"eid":eid,"capture":cap,
                        "event":dt(rec_time) if rec_time else cap,"context":context,"linked_by":"record" if record_identity_match(record, aliases) else "activity",
                        "after_capture_cutoff":cap > cutoff})
            related = str(record.get("source_resource_id") or record.get("parent_resource_id") or "").strip()
            if related and RESOURCE_RE.fullmatch(related) and related != res and not related.casefold().endswith(("_service", "_platform")):
                rp = resource_prefix(related)
                obs.append({"resource":related,"prefix":rp,"system":SYSTEMS.get(rp,"unknown_service"),
                            "category":PREFIX_CATEGORY.get(rp,"USER_PROFILE"),"record":{},
                            "text":"source_resource_id reference; verify source account state",                            "state":{"absent":False,"enabled":None,"restore":None,"raw":"source resource reference; state unknown","low":"unknown"},
                            "eid":eid,"capture":cap,"event":dt(rec_time) if rec_time else cap,
                            "context":{},"linked_by":"resource_reference","after_capture_cutoff":cap > cutoff})
        # Correlate log lines by trace_id: a trace is linked only if one line contains an exact identifier.
        if e["path"].suffix.lower() in {".sql", ".json"}:
            continue
        lines = e["lines"]
        trace_hits = set()
        trace_lines = defaultdict(list)
        for line in lines:
            m = re.search(r"\b(?:trace_id|requestId|request_id)(?:=|\s*:\s*)[\"]?([^\s,\"]+)", line, re.I)
            if not m: m = re.search(r"\btr-[A-Za-z0-9-]+\b", line, re.I)
            if m: trace_lines[m.group(1) if m.lastindex else m.group(0)].append(line)
            if exact_text_link(line, aliases) and m: trace_hits.add(m.group(1) if m.lastindex else m.group(0))
        for line in lines:
            if not exact_text_link(line, aliases):
                trace = re.search(r"\b(?:trace_id|requestId|request_id)(?:=|\s*:\s*)[\"]?([^\s,\"]+)", line, re.I)
                trace_key = trace.group(1) if trace else None
                if not trace_key:
                    bare = re.search(r"\btr-[A-Za-z0-9-]+\b", line, re.I)
                    trace_key = bare.group(0) if bare else None
                if not trace_key or trace_key not in trace_hits: continue
            timestamp = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)", line)
            evtime = dt(timestamp.group(1)) if timestamp else cap
            if evtime and evtime > cutoff: continue
            if requested_at and evtime and evtime < requested_at: continue
            for m in RESOURCE_RE.finditer(line):
                res = m.group(0)
                if res.casefold().endswith(("_service", "_platform")):
                    continue
                prefix = resource_prefix(res)
                state = parse_state({}, line, prefix)
                cat = PREFIX_CATEGORY.get(prefix, "")
                trace_m = re.search(r"\b(?:trace_id|requestId|request_id)(?:=|\s*:\s*)[\"]?([^\s,\"]+)", line, re.I)
                trace_key = trace_m.group(1) if trace_m else None
                if not trace_key:
                    bare = re.search(r"\btr-[A-Za-z0-9-]+\b", line, re.I)
                    trace_key = bare.group(0) if bare else None
                trace_text = " ".join(trace_lines.get(trace_key, [])) if trace_key else line
                if e["path"].suffix.lower() == ".pdf":
                    # Document text is the source context for a one-resource attachment.
                    trace_text = e["text"]
                    if re.search(r"SUPPORT_ATTACHMENT", trace_text, re.I): cat = "SUPPORT_ATTACHMENT"
                    elif re.search(r"SUPPORT_MESSAGE", trace_text, re.I): cat = "SUPPORT_MESSAGE"
                elif re.search(r"SUPPORT_ATTACHMENT", line, re.I): cat = "SUPPORT_ATTACHMENT"
                elif re.search(r"SUPPORT_MESSAGE", line, re.I): cat = "SUPPORT_MESSAGE"
                obs.append({"resource":res,"prefix":prefix,"system":SYSTEMS.get(prefix,"unknown_service"),"category":cat,
                            "record":{},"text":trace_text or line,"state":state,"eid":eid,"capture":cap,
                            "event":evtime or cap,"context":{},"linked_by":"trace_or_line","after_capture_cutoff":cap > cutoff})
        # PDF/OCR documents can identify one resource in a header and the subject in separate fields.
        # Allow document-level linking only when there is exactly one resource token in the whole document.
        if e["path"].suffix.lower() == ".pdf":
            doc_resources = {m.group(0) for m in RESOURCE_RE.finditer(e["text"])
                             if not m.group(0).casefold().endswith(("_service", "_platform"))}
            if len(doc_resources) == 1 and exact_text_link(e["text"], aliases):
                res = next(iter(doc_resources)); prefix = resource_prefix(res)
                obs.append({"resource":res,"prefix":prefix,"system":SYSTEMS.get(prefix,"unknown_service"),
                            "category":"SUPPORT_ATTACHMENT" if prefix == "support" else PREFIX_CATEGORY.get(prefix,""),
                            "record":{},"text":e["text"],"state":parse_state({},e["text"],prefix),"eid":eid,
                            "capture":cap,"event":cap,"context":{},"linked_by":"single_resource_document","after_capture_cutoff":cap > cutoff})
        # Activity-linked resources may be visible in an evidence line without the identifier on that line.
        for res, link in links.items():
            for line in lines:
                if not re.search(r"(?<![A-Za-z0-9_-])" + re.escape(res) + r"(?![A-Za-z0-9_-])", line, re.I): continue
                if exact_text_link(line, aliases): continue
                timestamp = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)", line)
                evtime = dt(timestamp.group(1)) if timestamp else cap
                if evtime and evtime > cutoff: continue
                if requested_at and evtime and evtime < requested_at: continue
                prefix = resource_prefix(res)
                obs.append({"resource":res,"prefix":prefix,"system":SYSTEMS.get(prefix,"unknown_service"),
                            "category":PREFIX_CATEGORY.get(prefix,""),"record":{},"text":line,
                            "state":parse_state({},line,prefix),"eid":eid,"capture":cap,"event":evtime or cap,
                            "context":{},"linked_by":"activity_corroborated"})
    # If an explicit LINK_RESOURCE_IDENTITY event names the user and resource but no readback
    # was captured, retain the link as an unknown state. This produces a future verification
    # step without claiming the resource is present or absent.
    observed_ids = {o["resource"] for o in obs}
    for res, link in links.items():
        if res in observed_ids: continue
        prefix = resource_prefix(res)
        corroborated = None
        details = link.get("details", "")
        refs = re.findall(r"\(([^()]+)\)", details)
        for e in evidence:
            cap = dt(e["meta"].get("captured_at"))
            if not cap or cap > cutoff or (requested_at and cap < requested_at): continue
            if any(ref and ref.casefold() in e["text"].casefold() and ref != res for ref in refs):
                corroborated = e; break
        if corroborated:
            obs.append({"resource":res,"prefix":prefix,"system":SYSTEMS.get(prefix,"unknown_service"),
                        "category":PREFIX_CATEGORY.get(prefix,""),"record":{},
                        "text":details + " " + corroborated["text"],
                        "state":{"absent":False,"enabled":None,"restore":None,"raw":"explicitly linked resource referenced in captured document","low":"present"},
                        "eid":corroborated["meta"]["file_id"],"capture":dt(corroborated["meta"].get("captured_at")),
                        "event":dt(corroborated["meta"].get("captured_at")),"context":{},"linked_by":"activity_corroborated"})
        else:
            obs.append({"resource":res,"prefix":prefix,"system":SYSTEMS.get(prefix,"unknown_service"),
                        "category":PREFIX_CATEGORY.get(prefix,""),"record":{},"text":details,
                        "state":{"absent":False,"enabled":None,"restore":None,"raw":"identity linked; current state unknown","low":"unknown"},
                        "eid":"","capture":None,"event":None,"context":{},"linked_by":"resource_reference"})
    # Deduplicate exact observations, keeping the same file/resource/line or row only once.
    uniq = {}
    for o in obs:
        key = (o["resource"], o["eid"], json.dumps(o["record"], sort_keys=True, default=str), o["text"])
        uniq[key] = o
    values = list(uniq.values())
    citable_resources = {o["resource"] for o in values if o.get("eid")}
    values = [o for o in values if o.get("eid") or o["resource"] not in citable_resources]
    return values, links


def rules_map():
    return {r["data_category"].strip().upper(): {"action":r["required_action"].strip().upper(),
            "condition":r.get("condition", "").strip()} for r in RULES}


def has_direct_pii(obs, aliases=None):
    if direct_identifiers(obs["record"]):
        return True
    text = obs.get("text", "")
    # Only count explicit identifier values; a user_id/customer_reference alone is not direct PII.
    if EMAIL_RE.search(text): return True
    if aliases and HASH_RE.search(text) and any(h in {x.casefold() for x in HASH_RE.findall(text)} for h in aliases["hashes"]): return True
    if re.search(r"(?:phone|mobile|contact_phone)\s*[=:]\s*\+?[0-9][0-9 ()-]{6,}[0-9]", text, re.I): return True
    if re.search(r"(?:full_name|display_name|customer_name|name)\s*[=:]\s*[\"]?[^,\"]{3,}", text, re.I): return True
    return False


def action_for(obs, links, aliases=None):
    cat, prefix, rec = obs["category"].upper(), obs["prefix"], obs["record"]
    policy = RULE_MAP.get(cat, {}).get("action", "DELETE")
    if prefix in {"data_flow"}: return "DATA_FLOW"
    if prefix == "backup": return "BACKUP"
    if prefix in {"audit_record", "legal_hold", "legal"} or cat in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return "RETAIN"
    if prefix == "tombstone": return "REDACT"
    # Exclusive attachments are governed by DELETE; shared support messages remain under REDACT.
    link = links.get(obs["resource"], {})
    if cat == "SUPPORT_MESSAGE" and (link.get("exclusive") or re.search(r"legacy_contact_index|belongs only to .*no other subject", obs.get("text", ""), re.I)): return "DELETE"
    # Standalone records with direct email/phone/hash/name fields are PII copies, not merely attributable analytics.
    # Analytics and product telemetry are anonymized per policy, even when a
    # structured row contains direct identifiers; do not escalate them to DELETE.
    if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        return RULE_MAP.get(cat, {}).get("action", "ANONYMIZE")
    return policy




def _uid_sort_key(uid):
    m = re.search(r"(\d+)$", str(uid or ""))
    return (0, int(m.group(1))) if m else (1, str(uid or ""))


def build_subject_field_index(evidence):
    identity_keys = ("email", "email_address", "customer_email", "contact_email", "old_email",
                     "primary_email", "owner_email", "requester_email", "subject_email",
                     "phone", "phone_number", "mobile", "contact_phone", "owner_phone",
                     "requester_phone", "subject_phone", "email_hash", "identifier_hash",
                     "subject_hash", "user_id", "subject_user_id", "subject_reference",
                     "customer_reference", "owner_user_id", "account_user_id")
    index = defaultdict(list)
    for e in evidence:
        cap = dt(e["meta"].get("captured_at"))
        for rec, ctx in e.get("records", []):
            rid = str(rec.get("resource_id") or rec.get("account_id") or ctx.get("resource_id") or "").strip()
            if not rid: continue
            if not any(str(rec.get(k) or "").strip() for k in identity_keys): continue
            rt = next((rec.get(k) or ctx.get(k) for k in
                       ("event_time", "observed_at", "snapshot_at", "captured_at", "updated_at", "indexed_at", "created_at", "timestamp")
                       if rec.get(k) or ctx.get(k)), None)
            index[rid].append((cap, dt(rt), bool(rt)))
    return index


def resource_has_subject_fields(index, resource, cutoff):
    for cap, rt, has_record_time in index.get(resource, []):
        if cap and cap > cutoff and (not has_record_time or rt is None or rt > cutoff): continue
        if rt and rt > cutoff: continue
        return True
    return False


_RESOURCE_RECORDS = {}
_RESOURCE_MENTIONS = {}
_TEXT_ID_CACHE = {}
_OBSERVATION_CACHE = {}

def build_evidence_indexes(evidence):
    """Build request-independent evidence indexes once for the whole run."""
    records_by_res = defaultdict(list)
    mentions = defaultdict(set)
    for i, e in enumerate(evidence):
        e["cap"] = dt(e["meta"].get("captured_at"))
        e["resource_mentions"] = {m.group(0) for m in RESOURCE_RE.finditer(e.get("text", ""))
                                  if not m.group(0).casefold().endswith(("_service", "_platform"))}
        for res in e["resource_mentions"]:
            mentions[res].add(i)
        for rec, ctx in e.get("records", []):
            rid = str(rec.get("resource_id") or rec.get("account_id") or ctx.get("resource_id") or "").strip()
            if rid:
                records_by_res[rid].append((i, rec, ctx))
    return dict(records_by_res), dict(mentions)

def find_resource_evidence(resource, evidence, cutoff, requested_at=None):
    """Return the best evidence-backed observation for an exact resource ID."""
    choices = []
    candidate_indices = set(_RESOURCE_MENTIONS.get(resource, set()))
    candidate_indices.update(i for i, _, _ in _RESOURCE_RECORDS.get(resource, []))
    for i in candidate_indices:
        e = evidence[i]
        cap = e.get("cap") or dt(e["meta"].get("captured_at"))
        pre_request_snapshot = any(k in e["meta"].get("file_path", "").lower()
                                   for k in ("service_resource_export", "customer_data_snapshot_bundle"))
        if cap is None or cap > cutoff or (requested_at and cap < requested_at and not pre_request_snapshot):
            continue
        for rec, ctx in e.get("records", []):
            rid = str(rec.get("resource_id") or rec.get("account_id") or ctx.get("resource_id") or "").strip()
            if rid != resource: continue
            rt = next((rec.get(k) or ctx.get(k) for k in
                       ("event_time", "observed_at", "snapshot_at", "captured_at", "updated_at", "indexed_at", "created_at", "timestamp")
                       if rec.get(k) or ctx.get(k)), None)
            if rt and not at_or_before(rt, cutoff): continue
            if requested_at and rt and dt(rt) and dt(rt) < requested_at and not resource.startswith(("audit_record_", "legal_hold_")): continue
            context = dict(ctx)
            context.setdefault("data_store", rec.get("data_store") or rec.get("system_id"))
            context.setdefault("collection", rec.get("collection"))
            path = norm(e["meta"].get("file_path"))
            specificity = (2 if resource.casefold() in path else 0)
            owning = SYSTEMS.get(resource_prefix(resource), "")
            specificity += 1 if owning and owning.casefold().split("_")[0] in path else 0
            choices.append((specificity, dt(rt) or cap, cap, e["meta"]["file_id"], rec, context, ""))
        if not e.get("records") and resource in e.get("resource_mentions", set()):
            for line in e.get("lines", []):
                if not re.search(r"(?<![A-Za-z0-9_-])" + re.escape(resource) + r"(?![A-Za-z0-9_-])", line, re.I): continue
                tm = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)", line)
                rt = dt(tm.group(1)) if tm else cap
                if rt and rt > cutoff: continue
                if requested_at and rt and rt < requested_at: continue
                path = norm(e["meta"].get("file_path"))
                specificity = (2 if resource.casefold() in path else 0)
                owning = SYSTEMS.get(resource_prefix(resource), "")
                specificity += 1 if owning and owning.casefold().split("_")[0] in path else 0
                choices.append((specificity, rt or cap, cap, e["meta"]["file_id"], {}, {}, line))
    if not choices: return None
    choices.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    _, rt, cap, eid, rec, context, line = choices[-1]
    prefix = resource_prefix(resource)
    category = record_category(rec, context, resource) if rec else PREFIX_CATEGORY.get(prefix, "")
    state = parse_state(rec, line, prefix)
    return {"resource": resource, "prefix": prefix, "system": get_resource_system(resource, context),
            "category": category, "record": rec, "text": line, "state": state,
            "eid": eid, "capture": cap, "event": rt, "context": context,
            "linked_by": "batch_activity_assignment", "after_capture_cutoff": False}


def build_batch_activity_assignments(requests, users, email_to_uid, audits, evidence, activities):
    """Link orphan resources only through balanced, timestamped activity batches.

    Within an exact reported_at batch, an unlinked resource is assigned only when the
    relevant activity/result bucket and the requests lacking that resource type have the
    same cardinality. Requests and events are ordered deterministically; resources that
    already carry structured identity fields are excluded from this fallback.
    """
    by_case = {}
    request_info = {}
    # Batch correlation can only assign resources when at least two requests share the
    # exact reported_at/status bucket. Avoid re-running a full evidence scan for singleton buckets.
    bucket_counts = defaultdict(int)
    for req in requests:
        bucket_counts[(req.get("reported_at", ""), norm(req.get("reported_status")))] += 1
    relevant_keys = {k for k, n in bucket_counts.items() if n > 1}
    subject_field_index = build_subject_field_index(evidence)
    for req in requests:
        if (req.get("reported_at", ""), norm(req.get("reported_status"))) not in relevant_keys:
            continue
        cutoff = dt(req.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
        requested = dt(req.get("requested_at"))
        if not deletion_intent(req.get("request_text", "")): continue
        uid, aliases = resolve_identity(req, users, email_to_uid, audits, cutoff)
        if not uid: continue
        obs, links = build_observations(evidence, activities, aliases, uid, cutoff, requested)
        _OBSERVATION_CACHE[req["case_id"]] = (copy.deepcopy(obs), copy.deepcopy(links))
        request_info[req["case_id"]] = {"req": req, "uid": uid, "aliases": aliases,
                                        "observed_prefixes": {o["prefix"] for o in obs},
                                        "observed_resources": {o["resource"] for o in obs}}
    prefix_for_event = {"DELETE_RECORD": "account", "ANONYMIZE_RECORD": "analytics",
                        "REDACT_RECORD": "support", "DISABLE_DATA_FLOW": "data_flow",
                        "BLOCK_RESTORE": "backup"}
    groups = defaultdict(list)
    for info in request_info.values():
        req = info["req"]
        groups[(req.get("reported_at", ""), norm(req.get("reported_status")))].append(info)
    directly_observed_resources = {r for info in request_info.values() for r in info["observed_resources"]}
    for (reported_text, status_norm), infos in groups.items():
        reported = dt(reported_text)
        if not reported: continue
        # Work by operation type. For DELETE_RECORD, reported result must agree with the
        # workflow claim; for other operations the event's own result is not the workflow status.
        for event_type, prefix in prefix_for_event.items():
            targets = [i for i in infos if prefix not in i["observed_prefixes"]]
            if not targets: continue
            expected_result = {"complete": "SUCCESS", "partially_complete": "PARTIAL",
                               "not_started": "FAILED"}.get(status_norm)
            if event_type == "DELETE_RECORD" and not expected_result: continue
            target_by_result = {expected_result: targets} if event_type == "DELETE_RECORD" else {"*": targets}
            for result_key, result_targets in target_by_result.items():
                candidates = []
                for a in activities:
                    if norm(a.get("event_type")).upper() != event_type: continue
                    if event_type == "DELETE_RECORD" and norm(a.get("reported_result")).upper() != result_key: continue
                    res = str(a.get("resource_id") or "").strip()
                    group_cutoff = max((dt(i["req"].get("audit_at")) or reported for i in result_targets), default=reported)
                    if not res or resource_prefix(res) != prefix or resource_has_subject_fields(subject_field_index, res, group_cutoff): continue
                    at = dt(a.get("event_time"))
                    if not at or at > reported or (reported - at).total_seconds() > 2 * 3600: continue
                    if res in directly_observed_resources: continue
                    group_cutoff_for_evidence = max((dt(i["req"].get("audit_at")) or reported for i in result_targets), default=reported)
                    has_scoped_evidence = any(
                        (e.get("cap") or dt(e["meta"].get("captured_at")) or datetime.max.replace(tzinfo=timezone.utc)) <= group_cutoff_for_evidence
                        for e in (evidence[i] for i in _RESOURCE_MENTIONS.get(res, set()))
                    )
                    if not has_scoped_evidence and prefix != "account": continue
                    # Candidate must be within every paired request's legal interval; checked after pairing.
                    candidates.append((at, res, a))
                # Keep one event per resource (earliest event in the request batch).
                unique = {}
                for at, res, a in sorted(candidates): unique.setdefault(res, (at, res, a))
                candidates = list(unique.values())
                if len(candidates) != len(result_targets) or not candidates: continue
                result_targets = sorted(result_targets, key=lambda i: _uid_sort_key(i["uid"]))
                candidates.sort(key=lambda x: (x[0], x[1]))
                pairings = list(zip(result_targets, candidates))
                if any((dt(info["req"].get("requested_at")) and event[0] < dt(info["req"].get("requested_at"))) or
                       (dt(info["req"].get("audit_at")) and event[0] > dt(info["req"].get("audit_at")))
                       for info, event in pairings):
                    continue
                for info, (at, res, activity) in pairings:
                    # Resource evidence must be available at the audit cutoff to support the link.
                    cutoff = dt(info["req"].get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
                    ev = find_resource_evidence(res, evidence, cutoff, dt(info["req"].get("requested_at")))
                    if ev:
                        by_case.setdefault(info["req"]["case_id"], []).append(ev)
    return by_case


def account_activity_candidate(req, activities, evidence, cutoff):
    """Resolve an orphan account lookup only when the activity/status/time evidence is unique."""
    reported = dt(req.get("reported_at")); requested = dt(req.get("requested_at"))
    if not reported: return None
    expected = {"COMPLETE": {"SUCCESS"}, "PARTIALLY_COMPLETE": {"PARTIAL", "PARTIALLY_COMPLETE"},
                "NOT_STARTED": {"FAILED", "FAILURE", "ERROR"}}.get(norm(req.get("reported_status")).upper(), set())
    candidates=[]
    for a in activities:
        if norm(a.get("event_type")) != "delete_record": continue
        res=str(a.get("resource_id") or "")
        if not res.startswith("account_"): continue
        at=dt(a.get("event_time"))
        if not at or at > cutoff or abs((at-reported).total_seconds()) > 2*3600: continue
        if requested and at < requested: continue
        if norm(a.get("reported_result")).upper() not in expected: continue
        candidates.append((abs((at-reported).total_seconds()), a, res))
    # Prefer a unique result matching the workflow claim. If none matches, a single nearby
    # account DELETE_RECORD may still establish the resource link; ambiguous candidates are skipped.
    if len(candidates)==1: return candidates[0][2], candidates[0][1]
    # If multiple same-status events exist in the broader window, accept a unique near-time event.
    near_status=[x for x in candidates if x[0] <= 15*60]
    if len(near_status)==1: return near_status[0][2],near_status[0][1]
    if not candidates:
        fallback=[]
        for a in activities:
            if norm(a.get("event_type")) != "delete_record": continue
            res=str(a.get("resource_id") or "")
            at=dt(a.get("event_time"))
            if not res.startswith("account_") or not at or at > cutoff: continue
            if abs((at-reported).total_seconds()) <= 2*3600 and (not requested or at >= requested): fallback.append((abs((at-reported).total_seconds()),a,res))
        if len(fallback)==1: return fallback[0][2],fallback[0][1]
        near_fallback=[x for x in fallback if x[0] <= 15*60]
        if len(near_fallback)==1: return near_fallback[0][2],near_fallback[0][1]
    return None


def make_plan(req, users, current_email_to_uid, audits, evidence, activities, batch_assignments=None):
    cutoff = dt(req.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    if not deletion_intent(req.get("request_text", "")): return "NOT_APPLICABLE", []
    uid, aliases = resolve_identity(req, users, current_email_to_uid, audits, cutoff)
    requested_at = dt(req.get("requested_at"))
    cached = _OBSERVATION_CACHE.get(req["case_id"])
    if cached is not None:
        observations, links = copy.deepcopy(cached)
    else:
        observations, links = build_observations(evidence, activities, aliases, uid, cutoff, requested_at)
    existing_resources = {o["resource"] for o in observations}
    for assigned in (batch_assignments or {}).get(req["case_id"], []):
        if assigned["resource"] not in existing_resources:
            observations.append(assigned); existing_resources.add(assigned["resource"])
    # If a resource was discovered in an uncitable late trace, recover its state and citation
    # from the best eligible point-in-time snapshot for that exact resource ID.
    for i, obs in enumerate(list(observations)):
        if not obs.get("eid"):
            snapshot = find_resource_evidence(obs["resource"], evidence, cutoff, requested_at)
            if snapshot and snapshot.get("eid"):
                observations[i] = snapshot
    citable_resources = {o["resource"] for o in observations if o.get("eid")}
    observations = [o for o in observations if o.get("eid") or o["resource"] not in citable_resources]
    orphan = None if any(o["prefix"] == "account" for o in observations) else account_activity_candidate(req, activities, evidence, cutoff)
    if orphan and not any(o["prefix"] == "account" for o in observations):
        res, activity = orphan
        account_scoped = [e for e in evidence
                          if e.get("cap") and e["cap"] <= cutoff
                          and (not requested_at or e["cap"] >= requested_at)
                          and any(x in e["meta"].get("file_path", "").lower()
                                  for x in ("account", "customer_data_inventory", "service_resource_export", "resource_lookup"))
                          and res in e.get("resource_mentions", set())]
        if not account_scoped:
            orphan = None
    if orphan and not any(o["prefix"] == "account" for o in observations):
        res, activity = orphan
        # A 404/empty account readback or absence from the eligible account snapshot is a verification target.
        eligible = [e for e in evidence if (dt(e["meta"].get("captured_at")) or datetime.max.replace(tzinfo=timezone.utc)) <= cutoff
                    and (not dt(req.get("requested_at")) or dt(e["meta"].get("captured_at")) >= dt(req.get("requested_at")))
                    and any(x in e["meta"].get("file_path", "").lower() for x in ("account", "customer_data_inventory", "service_resource_export", "resource_lookup"))]
        if eligible:
            eligible.sort(key=lambda e: (dt(e["meta"].get("captured_at")) or datetime.min.replace(tzinfo=timezone.utc), e["meta"]["file_id"]))
            ev=eligible[-1]
            prefix="account"
            observations.append({"resource":res,"prefix":prefix,"system":"account_service","category":"USER_PROFILE",
                                "record":{},"text":"explicit account deletion activity; snapshot scope supports absence check",
                                "state":{"absent":True,"enabled":None,"restore":None,"raw":"absent from eligible account snapshot","low":"absent"},
                                "eid":ev["meta"]["file_id"],"capture":dt(ev["meta"].get("captured_at")),
                                "event":dt(activity.get("event_time")),"context":{},"linked_by":"unique_activity_status"})
    # Link a resource lacking identifiers only when its own policy event is uniquely corroborated
    # by an eligible evidence snapshot near this request's reported_at. Ambiguous candidates are skipped.
    reported = dt(req.get("reported_at")); requested = dt(req.get("requested_at"))
    if reported and not observations:
        action_types = {"ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "CHECK_RESTORE_ACCESS", "CHECK_DATA_FLOW"}
        near=[]
        for a in activities:
            if norm(a.get("event_type")).upper() not in action_types: continue
            at=dt(a.get("event_time")); res=str(a.get("resource_id") or "")
            if not at or at > cutoff or abs((at-reported).total_seconds()) > 2*3600 or (requested and at < requested): continue
            if not any(o["resource"] == res for o in observations):
                candidates=[]
                for e in evidence:
                    cap=dt(e["meta"].get("captured_at"))
                    if not cap or cap > cutoff or (requested and cap < requested): continue
                    if re.search(r"(?<![A-Za-z0-9_-])"+re.escape(res)+r"(?![A-Za-z0-9_-])", e["text"], re.I): candidates.append(e)
                if candidates: near.append((res,a,candidates[-1]))
        for res,a,e in near:
            if len(near) != 1: continue
            prefix=resource_prefix(res); line=" ".join([a.get("event_type", ""),a.get("details", "")])
            state=parse_state({},line,prefix)
            et=norm(a.get("event_type"))
            if et == "check_restore_access" and re.search(r"can still be restored", line, re.I): state["restore"] = True
            if et == "check_data_flow" and re.search(r"remains enabled", line, re.I): state["enabled"] = True
            observations.append({"resource":res,"prefix":prefix,"system":SYSTEMS.get(prefix,"unknown_service"),
                                "category":PREFIX_CATEGORY.get(prefix,""),"record":{},"text":line,"state":state,
                                "eid":e["meta"]["file_id"],"capture":dt(e["meta"].get("captured_at")),
                                "event":dt(a.get("event_time")),"context":{},"linked_by":"unique_nearby_policy_event"})
    # Do not retain synthetic links unless an exact resource readback is citable.
    checked = []
    for o in observations:
        if o.get("linked_by") in {"unique_nearby_policy_event", "batch_activity_assignment"}:
            exact = find_resource_evidence(o["resource"], evidence, cutoff, requested_at)
            if not exact or not exact.get("eid") or exact.get("resource") != o["resource"]:
                continue
            o = exact
        checked.append(o)
    observations = checked
    # Apply explicit restore/data-flow activity to directly identity-linked resources.
    for o in observations:
        for a in activities:
            if a.get("resource_id") != o["resource"] or not at_or_before(a.get("event_time"), cutoff): continue
            if norm(a.get("event_type")) == "check_restore_access" and re.search(r"can still be restored", a.get("details", ""), re.I): o["state"]["restore"] = True
            if norm(a.get("event_type")) == "check_data_flow" and re.search(r"remains enabled", a.get("details", ""), re.I): o["state"]["enabled"] = True
        # Keep the latest observed state for each resource. Record/event time is primary; manifest capture breaks ties.
    latest = {}
    for o in observations:
        old = latest.get(o["resource"])
        score = (o["event"] or datetime.min.replace(tzinfo=timezone.utc), o["capture"], o["eid"])
        oldscore = (old["event"] or datetime.min.replace(tzinfo=timezone.utc), old["capture"], old["eid"]) if old else None
        if old is None or score >= oldscore: latest[o["resource"]] = o

    # A linked resource with multiple evidence types should use the record's category/state where available.
    resources = []
    for res, o in latest.items():
        prefix, cat, state = o["prefix"], o["category"], o["state"]
        policy_action = action_for(o, links, aliases)
        is_absent = state["absent"]
        finding = None
        compliant_op = None; compliant_state = None
        if o.get("linked_by") == "resource_reference":
            compliant_op, compliant_state = "VERIFY_RECORD_ABSENT", "ABSENT"
        elif prefix == "data_flow":
            if state["enabled"] is True or (state["enabled"] is None and re.search(r"\b(enabled|active|syncing|running)\b", state["low"])):
                finding = ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLED")
            elif state["enabled"] is False or re.search(r"\b(disabled|inactive|flow_off|flow_disabled)\b", state["low"]):
                compliant_op, compliant_state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        elif prefix == "backup":
            if state["restore"] is True:
                finding = ("REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCKED")
            elif state["restore"] is False:
                compliant_op, compliant_state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        elif policy_action == "RETAIN":
            if not is_absent:
                compliant_op, compliant_state = "VERIFY_RECORD_PRESENT", "PRESENT"
        elif prefix == "tombstone":
            # Identity-link descriptions can contain the subject's email; only the tombstone's
            # own fields (or explicit PII field assignments in a readback) prove exposure.
            tombstone_pii = direct_identifiers(o["record"]) or bool(re.search(
                r"(?:email|phone|email_hash|full_name|display_name|customer_name)\s*[=:]\s*(?!null|none|\"\"|''(?:,|\s|$))[^,\s]+",
                o.get("text", ""), re.I))
            if not is_absent and tombstone_pii:
                finding = ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED")
            elif not is_absent:
                compliant_op, compliant_state = "VERIFY_RECORD_REDACTED", "REDACTED"
            else:
                compliant_op, compliant_state = "VERIFY_RECORD_ABSENT", "ABSENT"
        elif is_absent:
            compliant_op, compliant_state = "VERIFY_RECORD_ABSENT", "ABSENT"
        elif policy_action == "DELETE":
            finding = ("REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT")
        elif policy_action == "REDACT":
            if has_direct_pii(o, aliases):
                finding = ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED")
            elif o["record"] or re.search(r"\b(pii|identifier|email|phone|personal data|matched_value)\b", state["low"]):
                # Shared content/retained context with no direct identifiers is already redacted.
                compliant_op, compliant_state = "VERIFY_RECORD_REDACTED", "REDACTED"
            else:
                finding = ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED")
        elif policy_action == "ANONYMIZE":
            # A stable user/reference key means the row remains attributable even if direct fields are gone.
            linked_by_stable = any(norm(o["record"].get(k)) == uid for k in ("user_id", "subject_user_id", "subject_reference", "customer_reference")) if uid and o["record"] else False
            if has_direct_pii(o, aliases) or linked_by_stable:
                finding = ("REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
            else:
                compliant_op, compliant_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        else:
            finding = ("REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT")
        # Evidence discovered in a later-captured file may reveal a pre-cutoff resource/event,
        # but cannot be cited. Do not turn it into a finding; require the relevant future check.
        if not o.get("eid"):
            if finding:
                if finding[0] == "REPORT_ACTIVE_DATA_FLOW":
                    compliant_op, compliant_state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
                elif finding[0] == "REPORT_RESTORE_RISK":
                    compliant_op, compliant_state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
                elif finding[0] == "REPORT_EXPOSED_PII":
                    compliant_op = "VERIFY_RECORD_REDACTED" if finding[2] == "REDACT_RECORD" else "VERIFY_RECORD_ANONYMIZED"
                    compliant_state = "REDACTED" if finding[2] == "REDACT_RECORD" else "ANONYMIZED"
                else:
                    compliant_op, compliant_state = "VERIFY_RECORD_ABSENT", "ABSENT"
                finding = None
            elif not compliant_op:
                if prefix == "data_flow": compliant_op, compliant_state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
                elif prefix == "backup": compliant_op, compliant_state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
                elif policy_action == "RETAIN": compliant_op, compliant_state = "VERIFY_RECORD_PRESENT", "PRESENT"
                elif policy_action == "REDACT": compliant_op, compliant_state = "VERIFY_RECORD_REDACTED", "REDACTED"
                elif policy_action == "ANONYMIZE": compliant_op, compliant_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
                else: compliant_op, compliant_state = "VERIFY_RECORD_ABSENT", "ABSENT"
        resources.append({"resource":res,"system":o["system"],"category":cat,"obs":o,"finding":finding,
                          "verify_op":compliant_op,"verify_state":compliant_state,"policy_action":policy_action})

    unknowns = [r for r in resources if r["obs"].get("linked_by") == "resource_reference"]
    findings = [r for r in resources if r["finding"]]
    # No findings is not enough on its own: there must be evidence-backed states to verify.
    if not resources:
        return "INCOMPLETE", []
    uncitable = [r for r in resources if not r["obs"].get("eid") and r["verify_op"]]
    status = "INCOMPLETE" if findings or unknowns or uncitable else "COMPLETE"
    steps = []
    if status == "INCOMPLETE":
        for r in findings:
            o = r["obs"]; f = r["finding"]
            steps.append(step("FINDING", r["system"], r["resource"], f[0], f[1], o["eid"]))
        for r in findings:
            f = r["finding"]
            steps.append(step("REMEDIATION", r["system"], r["resource"], f[2], f[3], ""))
        for r in resources:
            if r["finding"]:
                f = r["finding"]
                steps.append(step("VERIFICATION", r["system"], r["resource"], f[4], f[5], ""))
            elif r["verify_op"]:
                steps.append(step("VERIFICATION", r["system"], r["resource"], r["verify_op"], r["verify_state"], ""))
    else:
        for r in resources:
            if r["verify_op"]:
                steps.append(step("VERIFICATION", r["system"], r["resource"], r["verify_op"], r["verify_state"], r["obs"]["eid"]))
    # Ensure a retained security audit row is verified if linked, and only if observed.
    # All resources are evidence-backed; no suffix-based or name-based resource IDs are fabricated.
    steps.sort(key=lambda s: (PHASE_ORDER[s["phase"]], OP_ORDER.get(s["operation"], 999), s["system_id"], s["resource_id"]))
    for i, s in enumerate(steps, 1): s["step_no"] = i
    return status, steps


def validate(rows, requests, strict_full=False):
    assert len(rows) == len(requests), (len(rows), len(requests))
    expected = sorted(r["case_id"] for r in requests)
    actual = [r["case_id"] for r in rows]
    assert actual == expected, "missing, duplicate, or unsorted case IDs"
    allowed_status = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    for row in rows:
        assert row["deletion_status"] in allowed_status
        ss = json.loads(row["steps_json"])
        assert isinstance(ss, list)
        if row["deletion_status"] == "NOT_APPLICABLE": assert ss == []
        for i, s in enumerate(ss, 1):
            assert set(s) == {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
            assert s["step_no"] == i
            assert s["phase"] in PHASE_ORDER and s["operation"] in OP_ORDER
            assert s["system_id"] and s["resource_id"]
            if s["phase"] == "FINDING": assert s["evidence_id"]
            if row["deletion_status"] == "COMPLETE" and s["phase"] == "VERIFICATION": assert s["evidence_id"]
            if row["deletion_status"] == "INCOMPLETE" and s["phase"] in {"REMEDIATION", "VERIFICATION"}: assert s["evidence_id"] == ""
            if strict_full and s["evidence_id"] and s["evidence_id"].startswith("evidence_"):
                assert s["evidence_id"] in EVIDENCE_IDS, s["evidence_id"]


def main(input_path=None, output_path=None):
    global RULES, RULE_MAP, EVIDENCE_IDS
    requests = read_csv(Path(input_path) if input_path else DATA / "deletion_requests.csv")
    identities = read_csv(DATA / "user_identities.csv")
    audits = read_csv(DATA / "user_audit_log.csv")
    activities = read_csv(DATA / "system_activity.csv")
    manifest = read_csv(DATA / "evidence_files.csv")
    RULES = read_csv(DATA / "deletion_rules.csv")
    RULE_MAP = rules_map()
    EVIDENCE_IDS = {m["file_id"] for m in manifest}
    users, email_to_uid, audits = build_identity_indexes(identities, audits)
    evidence = load_evidence(manifest)
    global _RESOURCE_RECORDS, _RESOURCE_MENTIONS
    _RESOURCE_RECORDS, _RESOURCE_MENTIONS = build_evidence_indexes(evidence)
    # Include all unlabeled participant-facing requests as context for resolving ambiguous activity
    # batches, regardless of which request subset is being predicted in this invocation.
    context_requests = read_csv(DATA / "deletion_requests.csv")
    context_by_id = {r["case_id"]: r for r in context_requests}
    context_by_id.update({r["case_id"]: r for r in read_csv(DATA / "sample_deletion_requests.csv")})
    target_reported_times = {r.get("reported_at", "") for r in requests}
    relevant_context = [r for r in context_by_id.values() if r.get("reported_at", "") in target_reported_times]
    batch_assignments = build_batch_activity_assignments(relevant_context, users, email_to_uid, audits, evidence, activities)
    results = []
    for req in requests:
        status, steps = make_plan(req, users, email_to_uid, audits, evidence, activities, batch_assignments)
        results.append({"case_id": req["case_id"], "deletion_status": status,
                        "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    results.sort(key=lambda r: r["case_id"])
    target = Path(output_path) if output_path else OUT
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader(); w.writerows(results)
    validate(results, requests, strict_full=True)
    counts = defaultdict(int)
    for r in results: counts[r["deletion_status"]] += 1
    print(f"Wrote {len(results)} rows to {target}")
    print("Statuses:", dict(sorted(counts.items())))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", dest="input_path")
    ap.add_argument("--output", dest="output_path")
    args = ap.parse_args()
    main(args.input_path, args.output_path)
