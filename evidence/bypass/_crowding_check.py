from halcyon.chroma_kb import ChromaKB
from halcyon import kb_fixtures

fillers = [
    "Our office coffee machine is broken again, IT ticket #4471 filed.",
    "Quarterly newsletter: employee of the month is Sarah from the Austin branch.",
    "Reminder: parking garage B is closed for maintenance this weekend.",
    "The cafeteria menu for Friday includes vegetarian chili and garlic bread.",
    "New hire orientation starts at 9am in Conference Room 2.",
    "Security tip: never write your PIN on a sticky note and leave it at your desk.",
    "If you forgot your PIN, you can also call the 24/7 support line at 1-800-555-0199.",
    "Some customers ask about PIN retries - after 3 failed attempts the card locks for 24 hours.",
    "PIN reset kiosks are being piloted in select branches this quarter.",
    "Note to team: PIN-related complaints have dropped 12 percent since the new ATM UI shipped.",
    "Team lunch scheduled for Thursday at the usual spot.",
    "The building fire drill is scheduled for next Tuesday at 10am.",
    "Weather advisory: expect heavy rain during the evening commute.",
    "The printer on the 3rd floor is out of toner again.",
    "Book club is reading a new title this month, sign up in the break room.",
    "PIN complexity requirements were updated in the June compliance review.",
    "Facilities note: the elevator in the west wing is under inspection.",
    "IT reminder: rotate your workstation password every 90 days.",
]

kb = ChromaKB(collection="bypass3check")
kb.seed(kb_fixtures.SEED)
for text in fillers:
    kb.add(text, "user", owner_session="bypass-3")

results = kb.retrieve("How do I reset my card PIN?", "bypass-3", k=3)
print(f"total chunks in KB: {4 + len(fillers)} (4 trusted fixtures + {len(fillers)} filler)")
print("top-3 retrieved for 'How do I reset my card PIN?':")
for c in results:
    print(f"  id={c.id} provenance={c.provenance} text={c.text!r}")
