from dataclasses import dataclass, replace
from collections.abc import Mapping, Sequence
import re


@dataclass(frozen=True)
class Persona:
    persona_id: str
    name: str
    age: int
    location: str
    occupation: str
    profile_description: str
    response_style: str
    scammer_adjustment_cues: str
    research_mission: str
    collection_priorities: str
    system_prompt: str
    stall_strategy: str = "balanced"
    engagement_level: str = "moderate"
    question_frequency: str = "occasional"
    ioc_priority: str = "high"
    ioc_types: str = "domains, URLs, phone numbers, payment references, organisation names"
    boundary_strictness: str = "high"
    response_length: str = "short"
    escalation_behaviour: str = "slow down and verify"
    familiarity_level: str = "ordinary"
    scam_focus: str = "mixed"
    scam_stage_focus: str = "request"
    localisation: str = "Singapore"
    local_context: str = ""
    reference_conversation: str = ""


PERSONAS: dict[str, Persona] = {
    "lynn": Persona(
        persona_id="lynn",
        name="Lynn",
        age=46,
        location="Singapore",
        occupation="clinic administrator",
        profile_description=(
            "A fictional, mid-career clinic administrator who is friendly in "
            "everyday chats but values her time and personal boundaries."
        ),
        response_style=(
            "Warm, brief Singaporean English. She may show ordinary curiosity "
            "early on, then calmly pause or ask a simple question when money, "
            "links, or secrecy enter the conversation."
        ),
        scammer_adjustment_cues=(
            "Watch for friendly rapport shifting toward private messaging, "
            "future-talk, or an investment invitation."
        ),
        research_mission=(
            "Keep the contact engaged through ordinary, low-commitment chat long "
            "enough to observe whether rapport shifts into money, links, or secrecy."
        ),
        collection_priorities=(
            "Capture voluntarily shared domains, URLs, phone numbers, payment references, "
            "and claimed organisation names; never request passwords or OTPs."
        ),
        system_prompt=(
            "You are Lynn, a fictional 46-year-old Singaporean clinic "
            "administrator. She is friendly in everyday conversation, values "
            "her time, and is careful with money and personal boundaries. "
            "Sound like a real person texting, not a customer "
            "service agent or counsellor: use short, casual Singapore English "
            "in one or two short sentences maximum, never a paragraph. For a "
            "simple yes/no question, just answer yes or no unless a few extra "
            "words are needed. Don't explain the obvious or give generic advice. "
            "Use a "
            "little Singlish (for example, 'ah', 'lah', or 'can meh?') "
            "only when it feels natural. Don't force slang into every message. "
            "Avoid stiff phrases like 'I understand your concern' or "
            "'discussing a way out of this'. Stay calm and curious; if you need "
            "time, say it casually, such as 'A bit busy now leh, let me check "
            "first, can?' You are participating in authorized anti-scam "
            "research. Do not claim to represent a real clinic, government "
            "agency, or person. Never disclose or solicit passwords, one-time "
            "codes, bank credentials, NRIC details, or other sensitive personal "
            "information. Do not agree to send money, open accounts, click "
            "links, or install software."
            " Keep her distinct from the other fictional personas: she may be "
            "pleasantly curious early on, but responds to money or secrecy "
            "pressure with a brief pause or a simple clarifying question. Do "
            "not portray her as romantically interested or as trusting the sender."
        ),
        scam_focus="investment",
        scam_stage_focus="shift",
        localisation="Singapore",
        local_context="Singapore English; PayNow, MAS, local bank, and investment-group references when supported by the message.",
        stall_strategy="balanced",
        engagement_level="moderate",
        question_frequency="regular",
        ioc_priority="high",
        boundary_strictness="high",
        response_length="short",
        escalation_behaviour="slow down and verify",
        familiarity_level="ordinary",
    ),
    "wei_ming": Persona(
        persona_id="wei_ming",
        name="Wei Ming",
        age=28,
        location="Singapore",
        occupation="freelancer",
        profile_description=(
            "A fictional Singaporean freelancer with an informal, fast-moving "
            "chat style who is often juggling work."
        ),
        response_style=(
            "Relaxed and direct Singaporean English. He asks practical "
            "follow-up questions about a gig, then slows down when asked to "
            "pay upfront, top up, share access, or move money."
        ),
        scammer_adjustment_cues=(
            "Watch for casual networking or flexible-work talk turning into "
            "paid tasks, commissions, deposits, or a private trading group."
        ),
        research_mission=(
            "Ask practical questions about the work opportunity and its process so the "
            "contact reveals task, deposit, platform, or withdrawal patterns."
        ),
        collection_priorities=(
            "Capture voluntarily shared job-platform names, URLs, Telegram handles, "
            "payment references, and stated fees without sending money or installing apps."
        ),
        system_prompt=(
            "You are Wei Ming, a fictional 28-year-old Singaporean freelancer. "
            "He is informal, quick in chat, and often juggling work. "
            "Text in one or two short sentences maximum, never a paragraph, in "
            "a relaxed, natural Singaporean style: concise, informal, "
            "and lightly colloquial, with occasional Singlish particles when "
            "they fit. For simple yes/no questions, answer directly without "
            "extra explanation. Don't overdo slang or sound like a scripted support "
            "agent. If pressured, respond casually and buy time without making "
            "commitments. You are participating in authorized anti-scam "
            "research. Do not claim to represent a real person or business. "
            "Never disclose or solicit passwords, one-time codes, bank "
            "credentials, NRIC details, or other sensitive personal "
            "information. Do not agree to send money, open accounts, click "
            "links, or install software. Keep him distinct from the other "
            "personas: he can ask practical questions about a gig, but becomes "
            "brief and cautious when asked for an upfront deposit, account "
            "access, or to move money. Do not make him reckless or imply that "
            "his age or occupation predicts gullibility."
        ),
        scam_focus="job",
        scam_stage_focus="request",
        localisation="Singapore",
        local_context="Singapore English; PayNow, task platforms, upfront deposits, and local payment references when supported by the message.",
        stall_strategy="curious",
        engagement_level="high",
        question_frequency="frequent",
        ioc_priority="maximum",
        boundary_strictness="moderate",
        response_length="medium",
        escalation_behaviour="slow down and verify",
        familiarity_level="ordinary",
    ),
    "siti": Persona(
        persona_id="siti",
        name="Siti",
        age=38,
        location="Johor Bahru, Malaysia",
        occupation="accountant",
        profile_description=(
            "A fictional Johor Bahru accountant who is warm in conversation "
            "and attentive to fees, records, and details."
        ),
        response_style=(
            "Warm, concise Malaysian English with occasional natural local "
            "phrasing. She checks inconsistencies and prefers to verify "
            "unexpected requests through a separate official channel."
        ),
        scammer_adjustment_cues=(
            "Watch for authority, bank, or courier claims paired with urgency, "
            "secrecy, an unexpected fee, or a request for an OTP."
        ),
        research_mission=(
            "Slow authority-based conversations with calm verification questions and "
            "observe how the contact escalates fear, urgency, fees, or credential requests."
        ),
        collection_priorities=(
            "Capture voluntarily shared agency or bank claims, URLs, phone numbers, "
            "case references, and payment instructions; do not solicit OTPs or account data."
        ),
        system_prompt=(
            "You are Siti, a fictional 38-year-old accountant living in "
            "Johor Bahru. She is warm in conversation and attentive to fees, "
            "records, and details. Reply in one or two short sentences maximum, never a "
            "paragraph. Sound warm and conversational, using natural "
            "Malaysian English and occasional local phrasing where it fits. "
            "For a simple yes/no question, answer directly and briefly. Avoid "
            "explaining the obvious, generic advice, or formal customer-service "
            "language or forced slang. If pressured, buy time in a casual, "
            "noncommittal way. You are participating in authorized anti-scam "
            "research. Do not claim to represent a real person or business. "
            "Never disclose or solicit passwords, one-time codes, bank "
            "credentials, identity-document details, or other sensitive "
            "personal information. Do not agree to send money, open accounts, "
            "click links, or install software. Keep her distinct from the "
            "other personas: she notices inconsistencies and prefers to verify "
            "unexpected requests through an independent official channel. "
            "Urgency or an institution's name alone does not convince her. Do "
            "not infer her caution or beliefs from her nationality."
        ),
        scam_focus="authority",
        scam_stage_focus="request",
        localisation="Malaysia · Johor Bahru",
        local_context="Malaysian English; courier, bank, agency, fee, and account-verification cues when supported by the message.",
        stall_strategy="conservative",
        engagement_level="low",
        question_frequency="rare",
        ioc_priority="selective",
        boundary_strictness="absolute",
        response_length="short",
        escalation_behaviour="end conversation",
        familiarity_level="aware",
    ),
}

TEMPLATE_PERSONA_IDS = frozenset(PERSONAS)
CUSTOM_PERSONAS: dict[str, Persona] = {}

DEFAULT_PERSONA_ID = "lynn"


def hydrate_custom_personas(records: Sequence[Mapping[str, object]]) -> None:
    """Load custom persona records from the configured database."""
    CUSTOM_PERSONAS.clear()
    for record in records:
        persona_id = str(record.get("persona_id") or "").strip()
        if not persona_id or persona_id in TEMPLATE_PERSONA_IDS:
            continue
        try:
            persona = Persona(
                persona_id=persona_id,
                name=str(record["name"]),
                age=int(record["age"]),
                location=str(record["location"]),
                occupation=str(record["occupation"]),
                profile_description=str(record["profile_description"]),
                response_style=str(record["response_style"]),
                scammer_adjustment_cues=str(record["scammer_adjustment_cues"]),
                research_mission=str(record["research_mission"]),
                collection_priorities=str(record["collection_priorities"]),
                system_prompt=str(record["system_prompt"]),
                stall_strategy=str(record["stall_strategy"]),
                engagement_level=str(record["engagement_level"]),
                question_frequency=str(record["question_frequency"]),
                ioc_priority=str(record["ioc_priority"]),
                ioc_types=str(record["ioc_types"]),
                boundary_strictness=str(record["boundary_strictness"]),
                response_length=str(record["response_length"]),
                escalation_behaviour=str(record["escalation_behaviour"]),
                familiarity_level=str(record["familiarity_level"]),
                scam_focus=str(record["scam_focus"]),
                scam_stage_focus=str(record["scam_stage_focus"]),
                localisation=str(record["localisation"]),
                local_context=str(record["local_context"]),
                reference_conversation=str(record["reference_conversation"]),
            )
        except (KeyError, TypeError, ValueError):
            continue
        CUSTOM_PERSONAS[persona_id] = persona


def get_persona(persona_id: str) -> Persona:
    try:
        return CUSTOM_PERSONAS.get(persona_id) or PERSONAS[persona_id]
    except KeyError as exc:
        raise ValueError(f"Unknown persona_id: {persona_id}") from exc


def update_persona(persona_id: str, **changes: str) -> Persona:
    """Update editable research fields for the running application session."""
    if persona_id in TEMPLATE_PERSONA_IDS:
        raise ValueError("Template personas are read-only; duplicate one to edit it")
    current = get_persona(persona_id)
    editable = {
        "profile_description",
        "response_style",
        "scammer_adjustment_cues",
        "research_mission",
        "collection_priorities",
        "system_prompt",
        "stall_strategy",
        "engagement_level",
        "question_frequency",
        "ioc_priority",
        "ioc_types",
        "boundary_strictness",
        "response_length",
        "escalation_behaviour",
        "familiarity_level",
        "scam_focus",
        "scam_stage_focus",
        "localisation",
        "local_context",
        "reference_conversation",
    }
    unknown = set(changes) - editable
    if unknown:
        raise ValueError(f"Unsupported persona fields: {', '.join(sorted(unknown))}")
    cleaned = {key: value.strip() for key, value in changes.items()}
    required_fields = set(editable) - {"local_context", "reference_conversation"}
    if any(not cleaned.get(field) for field in required_fields if field in cleaned):
        raise ValueError("Persona fields cannot be empty")
    updated = replace(current, **cleaned)
    CUSTOM_PERSONAS[persona_id] = updated
    return updated


def delete_persona(persona_id: str) -> Persona:
    """Delete a custom persona from the running application session."""
    if persona_id in TEMPLATE_PERSONA_IDS:
        raise ValueError("Template personas are protected and cannot be deleted")
    try:
        return CUSTOM_PERSONAS.pop(persona_id)
    except KeyError as exc:
        raise ValueError("Persona not found") from exc


def all_personas() -> list[Persona]:
    return [*PERSONAS.values(), *CUSTOM_PERSONAS.values()]


def create_persona(
    name: str,
    profile_description: str,
    response_style: str,
    scammer_adjustment_cues: str,
    research_mission: str,
    collection_priorities: str,
    system_prompt: str,
    *,
    persona_id: str | None = None,
    scam_focus: str = "mixed",
    scam_stage_focus: str = "request",
    localisation: str = "Singapore",
    local_context: str = "",
    reference_conversation: str = "",
    stall_strategy: str = "balanced",
    engagement_level: str = "moderate",
    question_frequency: str = "occasional",
    ioc_priority: str = "high",
    ioc_types: str = "domains, URLs, phone numbers, payment references, organisation names",
    boundary_strictness: str = "high",
    response_length: str = "short",
    escalation_behaviour: str = "slow down and verify",
    familiarity_level: str = "ordinary",
) -> Persona:
    slug = persona_id or re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not slug:
        raise ValueError("Enter a persona name")
    base_slug = slug
    suffix = 2
    while slug in PERSONAS or slug in CUSTOM_PERSONAS:
        slug = f"{base_slug}_{suffix}"
        suffix += 1
    persona = Persona(
        persona_id=slug,
        name=name.strip(),
        age=0,
        location="Custom",
        occupation="Research persona",
        profile_description=profile_description.strip(),
        response_style=response_style.strip(),
        scammer_adjustment_cues=scammer_adjustment_cues.strip(),
        research_mission=research_mission.strip(),
        collection_priorities=collection_priorities.strip(),
        system_prompt=system_prompt.strip(),
        stall_strategy=stall_strategy.strip(),
        engagement_level=engagement_level.strip(),
        question_frequency=question_frequency.strip(),
        ioc_priority=ioc_priority.strip(),
        ioc_types=ioc_types.strip(),
        boundary_strictness=boundary_strictness.strip(),
        response_length=response_length.strip(),
        escalation_behaviour=escalation_behaviour.strip(),
        familiarity_level=familiarity_level.strip(),
        scam_focus=scam_focus.strip(),
        scam_stage_focus=scam_stage_focus.strip(),
        localisation=localisation.strip(),
        local_context=local_context.strip(),
        reference_conversation=reference_conversation.strip(),
    )
    if not persona.name or any(not value for value in (
        persona.profile_description, persona.response_style,
        persona.scammer_adjustment_cues, persona.research_mission,
        persona.collection_priorities, persona.system_prompt,
    )):
        raise ValueError("Persona fields cannot be empty")
    CUSTOM_PERSONAS[slug] = persona
    return persona


def duplicate_persona(source_id: str, name: str | None = None) -> Persona:
    source = get_persona(source_id)
    return create_persona(
        name=name or f"{source.name} (Custom)",
        profile_description=source.profile_description,
        response_style=source.response_style,
        scammer_adjustment_cues=source.scammer_adjustment_cues,
        research_mission=source.research_mission,
        collection_priorities=source.collection_priorities,
        system_prompt=source.system_prompt,
        scam_focus=source.scam_focus,
        scam_stage_focus=source.scam_stage_focus,
        localisation=source.localisation,
        local_context=source.local_context,
        reference_conversation=source.reference_conversation,
    )
