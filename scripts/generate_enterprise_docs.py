#!/usr/bin/env python3
"""
Enterprise Document Generator for RAG Torture Testing

Generates large, interconnected documents that simulate real enterprise data:
- Employee directories (5000+ employees)
- Salary/compensation data (separate, requires cross-doc join)
- Org hierarchy with complex reporting chains
- Policy documents with multiple versions
- Meeting notes with conflicting information
- Project documentation scattered across files
- Acronym/jargon glossaries
- Cross-referenced procedures

Each document set has KNOWN GROUND TRUTH answers for testing.

Usage:
    python scripts/generate_enterprise_docs.py ./output_dir
    python scripts/generate_enterprise_docs.py ./output_dir --employees 10000
"""

import argparse
import csv
import json
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Seed for reproducibility - same docs every time
random.seed(42)

# ============================================================================
# DATA GENERATORS
# ============================================================================

FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Lisa", "Daniel", "Nancy",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Dorothy", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary", "Amy",
    "Nicholas", "Angela", "Eric", "Shirley", "Jonathan", "Anna", "Stephen", "Brenda",
    "Larry", "Pamela", "Justin", "Emma", "Scott", "Nicole", "Brandon", "Helen",
    "Benjamin", "Samantha", "Samuel", "Katherine", "Raymond", "Christine", "Gregory", "Debra",
    "Frank", "Rachel", "Alexander", "Carolyn", "Patrick", "Janet", "Jack", "Catherine",
    "Wei", "Aisha", "Mohammed", "Priya", "Hiroshi", "Fatima", "Carlos", "Mei",
    "Oluwaseun", "Ananya", "Dmitri", "Yuki", "Alejandro", "Zainab", "Raj", "Ling",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Chen", "Wang", "Kim", "Patel", "Singh", "Kumar",
    "Zhang", "Li", "Liu", "Yang", "Huang", "Zhao", "Wu", "Zhou",
    "O'Brien", "Murphy", "Kelly", "Sullivan", "McCarthy", "O'Connor", "Walsh", "Burke",
    "Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker",
]

DEPARTMENTS = [
    "Engineering", "Sales", "Marketing", "Finance", "Human Resources",
    "Legal", "Operations", "Customer Success", "Product", "Data Science",
    "IT Infrastructure", "Security", "Compliance", "Research", "Design",
]

LOCATIONS = [
    "HQ - San Francisco", "NYC Office", "Austin Hub", "Seattle Campus",
    "London Office", "Singapore Office", "Toronto Office", "Remote - US",
    "Remote - Europe", "Remote - APAC", "Denver Office", "Chicago Office",
]

JOB_LEVELS = ["IC1", "IC2", "IC3", "IC4", "IC5", "M1", "M2", "M3", "D1", "D2", "VP", "SVP", "C-Level"]

PROJECTS = [
    ("Project Phoenix", "PRJ-001", "Platform modernization initiative"),
    ("Project Atlas", "PRJ-002", "Global expansion program"),
    ("Project Lighthouse", "PRJ-003", "Customer analytics overhaul"),
    ("Project Velocity", "PRJ-004", "CI/CD pipeline optimization"),
    ("Project Shield", "PRJ-005", "Security infrastructure upgrade"),
    ("Project Horizon", "PRJ-006", "Next-gen product development"),
    ("Project Catalyst", "PRJ-007", "Process automation"),
    ("Project Mosaic", "PRJ-008", "Data integration platform"),
    ("Project Apex", "PRJ-009", "Executive dashboard"),
    ("Project Zenith", "PRJ-010", "Cloud migration phase 2"),
]

ACRONYMS = {
    "TPS": "Technical Performance Summary",
    "KPI": "Key Performance Indicator",
    "OKR": "Objectives and Key Results",
    "SLA": "Service Level Agreement",
    "RACI": "Responsible, Accountable, Consulted, Informed",
    "CSAT": "Customer Satisfaction Score",
    "NPS": "Net Promoter Score",
    "ARR": "Annual Recurring Revenue",
    "MRR": "Monthly Recurring Revenue",
    "CAC": "Customer Acquisition Cost",
    "LTV": "Lifetime Value",
    "EBITDA": "Earnings Before Interest, Taxes, Depreciation, and Amortization",
    "P&L": "Profit and Loss Statement",
    "QBR": "Quarterly Business Review",
    "RFP": "Request for Proposal",
    "SOW": "Statement of Work",
    "UAT": "User Acceptance Testing",
    "MVP": "Minimum Viable Product",
    "POC": "Proof of Concept",
    "EOD": "End of Day",
    "WFH": "Work From Home",
    "PTO": "Paid Time Off",
    "HRIS": "Human Resources Information System",
    "SSO": "Single Sign-On",
    "MFA": "Multi-Factor Authentication",
    "VPN": "Virtual Private Network",
    "API": "Application Programming Interface",
    "SDK": "Software Development Kit",
    "CI/CD": "Continuous Integration/Continuous Deployment",
    "SRE": "Site Reliability Engineering",
}


class EnterpriseDataGenerator:
    """Generates interconnected enterprise documents."""

    def __init__(self, output_dir: Path, num_employees: int = 5000):
        self.output_dir = output_dir
        self.num_employees = num_employees
        self.employees = []
        self.ground_truth = {}  # Stores known answers for testing

        output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self):
        """Generate all document sets."""
        print(f"Generating enterprise documents in {self.output_dir}")
        print(f"Target: {self.num_employees} employees\n")

        # Generate interconnected data
        self._generate_employees()
        self._generate_salary_data()
        self._generate_org_hierarchy()
        self._generate_project_assignments()
        self._generate_policy_versions()
        self._generate_meeting_notes()
        self._generate_acronym_glossary()
        self._generate_procedures()
        self._generate_quarterly_reports()

        # Save ground truth for testing
        self._save_ground_truth()

        print(f"\n✓ Generated {len(list(self.output_dir.glob('*')))} files")
        print(f"✓ Ground truth saved to ground_truth.json")

    def _generate_employees(self):
        """Generate employee directory - main entity table."""
        print("Generating employee directory...")

        # Generate org structure first (executives, directors, managers, ICs)
        levels = {
            "C-Level": 5,
            "SVP": 10,
            "VP": 25,
            "D2": 40,
            "D1": 60,
            "M3": 100,
            "M2": 200,
            "M1": 400,
        }
        ic_count = self.num_employees - sum(levels.values())

        emp_id = 1000

        # Generate leadership first
        for level, count in levels.items():
            for _ in range(count):
                emp = self._create_employee(f"E{emp_id:05d}", level)
                self.employees.append(emp)
                emp_id += 1

        # Generate ICs
        ic_levels = ["IC1", "IC2", "IC3", "IC4", "IC5"]
        for _ in range(ic_count):
            level = random.choices(ic_levels, weights=[15, 30, 30, 20, 5])[0]
            emp = self._create_employee(f"E{emp_id:05d}", level)
            self.employees.append(emp)
            emp_id += 1

        # Assign managers (skip C-levels who report to no one internally)
        self._assign_managers()

        # Write employee directory CSV
        with open(self.output_dir / "employee_directory.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "employee_id", "first_name", "last_name", "email",
                "department", "job_title", "job_level", "location",
                "start_date", "manager_id", "status"
            ])
            writer.writeheader()
            for emp in self.employees:
                writer.writerow({
                    "employee_id": emp["id"],
                    "first_name": emp["first_name"],
                    "last_name": emp["last_name"],
                    "email": emp["email"],
                    "department": emp["department"],
                    "job_title": emp["title"],
                    "job_level": emp["level"],
                    "location": emp["location"],
                    "start_date": emp["start_date"],
                    "manager_id": emp.get("manager_id", ""),
                    "status": emp["status"],
                })

        # Store some ground truth
        engineering_count = len([e for e in self.employees if e["department"] == "Engineering"])
        remote_count = len([e for e in self.employees if "Remote" in e["location"]])

        self.ground_truth["total_employees"] = len(self.employees)
        self.ground_truth["engineering_headcount"] = engineering_count
        self.ground_truth["remote_employees"] = remote_count

        print(f"  → {len(self.employees)} employees generated")

    def _create_employee(self, emp_id: str, level: str) -> dict:
        """Create a single employee record."""
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        dept = random.choice(DEPARTMENTS)

        # Title based on level and department
        if level.startswith("C"):
            title = f"Chief {dept} Officer" if dept != "Engineering" else "Chief Technology Officer"
        elif level == "SVP":
            title = f"SVP of {dept}"
        elif level == "VP":
            title = f"VP of {dept}"
        elif level.startswith("D"):
            title = f"Director, {dept}"
        elif level.startswith("M"):
            title = f"Manager, {dept}"
        else:
            titles = {
                "Engineering": ["Software Engineer", "Senior Software Engineer", "Staff Engineer", "Principal Engineer", "Distinguished Engineer"],
                "Sales": ["Account Executive", "Senior AE", "Enterprise AE", "Strategic AE", "Principal AE"],
                "Marketing": ["Marketing Specialist", "Marketing Manager", "Senior Marketing Manager", "Marketing Lead", "Principal Marketing"],
                "Finance": ["Financial Analyst", "Senior Analyst", "Finance Manager", "Senior Finance Manager", "Principal Finance"],
                "Human Resources": ["HR Coordinator", "HR Specialist", "HR Business Partner", "Senior HRBP", "Principal HRBP"],
            }
            level_idx = int(level[2]) - 1 if level.startswith("IC") else 2
            dept_titles = titles.get(dept, ["Specialist", "Senior Specialist", "Lead", "Senior Lead", "Principal"])
            title = dept_titles[min(level_idx, len(dept_titles) - 1)]

        # Random start date (1-15 years ago)
        days_ago = random.randint(30, 15 * 365)
        start_date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")

        return {
            "id": emp_id,
            "first_name": first,
            "last_name": last,
            "email": f"{first.lower()}.{last.lower()}@company.com",
            "department": dept,
            "title": title,
            "level": level,
            "location": random.choice(LOCATIONS),
            "start_date": start_date,
            "status": random.choices(["Active", "On Leave", "Terminated"], weights=[95, 3, 2])[0],
        }

    def _assign_managers(self):
        """Assign managers to create org hierarchy."""
        # Group by level
        by_level = {}
        for emp in self.employees:
            level = emp["level"]
            if level not in by_level:
                by_level[level] = []
            by_level[level].append(emp)

        # Manager assignment order
        manager_levels = ["C-Level", "SVP", "VP", "D2", "D1", "M3", "M2", "M1"]
        report_levels = ["SVP", "VP", "D2", "D1", "M3", "M2", "M1", "IC5", "IC4", "IC3", "IC2", "IC1"]

        for i, level in enumerate(report_levels):
            if level not in by_level:
                continue
            # Find potential managers (one or two levels up)
            potential_managers = []
            for mgr_level in manager_levels[:max(0, manager_levels.index(level) if level in manager_levels else len(manager_levels))]:
                potential_managers.extend(by_level.get(mgr_level, []))

            if not potential_managers:
                continue

            # Prefer same-department managers
            for emp in by_level[level]:
                same_dept = [m for m in potential_managers if m["department"] == emp["department"]]
                if same_dept:
                    emp["manager_id"] = random.choice(same_dept)["id"]
                else:
                    emp["manager_id"] = random.choice(potential_managers)["id"]

    def _generate_salary_data(self):
        """Generate salary data in SEPARATE file (requires join)."""
        print("Generating compensation data...")

        # Salary bands by level
        salary_bands = {
            "IC1": (60000, 90000),
            "IC2": (80000, 120000),
            "IC3": (100000, 150000),
            "IC4": (130000, 200000),
            "IC5": (170000, 280000),
            "M1": (120000, 180000),
            "M2": (150000, 220000),
            "M3": (180000, 280000),
            "D1": (200000, 320000),
            "D2": (250000, 400000),
            "VP": (300000, 500000),
            "SVP": (400000, 700000),
            "C-Level": (500000, 1500000),
        }

        compensation_data = []
        total_payroll = 0
        highest_paid = None
        highest_salary = 0

        for emp in self.employees:
            if emp["status"] == "Terminated":
                continue

            band = salary_bands.get(emp["level"], (50000, 80000))
            base_salary = random.randint(band[0], band[1])

            # Bonus as percentage of salary
            bonus_pct = random.uniform(0, 0.3) if emp["level"] not in ["IC1", "IC2"] else random.uniform(0, 0.1)
            bonus = int(base_salary * bonus_pct)

            # Stock (higher levels get more)
            stock_multiplier = {"IC1": 0, "IC2": 0.1, "IC3": 0.2, "IC4": 0.4, "IC5": 0.6,
                               "M1": 0.3, "M2": 0.5, "M3": 0.7, "D1": 1.0, "D2": 1.5,
                               "VP": 2.0, "SVP": 3.0, "C-Level": 5.0}.get(emp["level"], 0)
            stock_value = int(base_salary * stock_multiplier)

            total_comp = base_salary + bonus + stock_value
            total_payroll += base_salary

            if total_comp > highest_salary:
                highest_salary = total_comp
                highest_paid = emp

            compensation_data.append({
                "employee_id": emp["id"],
                "base_salary": base_salary,
                "bonus_target": bonus,
                "stock_value": stock_value,
                "total_compensation": total_comp,
                "pay_grade": emp["level"],
                "currency": "USD",
                "last_review_date": (datetime.now() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
            })

        # Write compensation CSV
        with open(self.output_dir / "compensation_data_confidential.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "employee_id", "base_salary", "bonus_target", "stock_value",
                "total_compensation", "pay_grade", "currency", "last_review_date"
            ])
            writer.writeheader()
            writer.writerows(compensation_data)

        # Ground truth - requires JOIN between employee and compensation
        engineering_salaries = []
        for emp in self.employees:
            if emp["department"] == "Engineering" and emp["status"] == "Active":
                comp = next((c for c in compensation_data if c["employee_id"] == emp["id"]), None)
                if comp:
                    engineering_salaries.append(comp["base_salary"])

        self.ground_truth["avg_engineering_salary"] = int(sum(engineering_salaries) / len(engineering_salaries)) if engineering_salaries else 0
        self.ground_truth["total_payroll"] = total_payroll
        self.ground_truth["highest_paid_employee"] = f"{highest_paid['first_name']} {highest_paid['last_name']}" if highest_paid else ""
        self.ground_truth["highest_compensation"] = highest_salary

        print(f"  → {len(compensation_data)} compensation records")

    def _generate_org_hierarchy(self):
        """Generate org chart as nested JSON (tests hierarchy traversal)."""
        print("Generating org hierarchy...")

        # Find CEO
        ceo = next((e for e in self.employees if e["level"] == "C-Level" and "Chief Executive" in e.get("title", "")),
                   next((e for e in self.employees if e["level"] == "C-Level"), None))

        def build_tree(manager_id: str, depth: int = 0) -> dict:
            manager = next((e for e in self.employees if e["id"] == manager_id), None)
            if not manager:
                return {}

            reports = [e for e in self.employees if e.get("manager_id") == manager_id]

            return {
                "id": manager["id"],
                "name": f"{manager['first_name']} {manager['last_name']}",
                "title": manager["title"],
                "department": manager["department"],
                "level": manager["level"],
                "direct_reports": [build_tree(r["id"], depth + 1) for r in reports[:20]] if depth < 4 else [],  # Limit depth
                "direct_report_count": len(reports),
            }

        if ceo:
            org_tree = build_tree(ceo["id"])

            with open(self.output_dir / "org_hierarchy.json", "w") as f:
                json.dump(org_tree, f, indent=2)

            # Ground truth - count levels
            def count_at_level(node, target_level, current=0):
                count = 1 if current == target_level else 0
                for report in node.get("direct_reports", []):
                    count += count_at_level(report, target_level, current + 1)
                return count

            self.ground_truth["ceo_name"] = f"{ceo['first_name']} {ceo['last_name']}"
            self.ground_truth["ceo_direct_reports"] = len([e for e in self.employees if e.get("manager_id") == ceo["id"]])

        print(f"  → Org hierarchy generated")

    def _generate_project_assignments(self):
        """Generate project assignments (many-to-many relationship)."""
        print("Generating project assignments...")

        assignments = []
        project_members = {p[1]: [] for p in PROJECTS}

        for emp in self.employees:
            if emp["status"] != "Active":
                continue

            # Each employee on 0-3 projects
            num_projects = random.choices([0, 1, 2, 3], weights=[20, 40, 30, 10])[0]
            emp_projects = random.sample(PROJECTS, min(num_projects, len(PROJECTS)))

            for proj_name, proj_id, proj_desc in emp_projects:
                role = random.choice(["Contributor", "Lead", "Reviewer", "Stakeholder"])
                allocation = random.choice([25, 50, 75, 100])

                assignments.append({
                    "employee_id": emp["id"],
                    "employee_name": f"{emp['first_name']} {emp['last_name']}",
                    "project_id": proj_id,
                    "project_name": proj_name,
                    "role": role,
                    "allocation_percent": allocation,
                    "start_date": (datetime.now() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
                })
                project_members[proj_id].append(emp["id"])

        with open(self.output_dir / "project_assignments.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "employee_id", "employee_name", "project_id", "project_name",
                "role", "allocation_percent", "start_date"
            ])
            writer.writeheader()
            writer.writerows(assignments)

        # Ground truth
        phoenix_members = len(project_members.get("PRJ-001", []))
        self.ground_truth["project_phoenix_members"] = phoenix_members
        self.ground_truth["total_project_assignments"] = len(assignments)

        print(f"  → {len(assignments)} project assignments")

    def _generate_policy_versions(self):
        """Generate multiple versions of policy documents (tests version confusion)."""
        print("Generating policy documents...")

        policies = [
            {
                "name": "Travel Policy",
                "versions": [
                    {"version": "1.0", "date": "2022-01-15", "status": "SUPERSEDED",
                     "content": "All business travel requires VP approval. Travel expenses must be submitted within 30 days. Maximum hotel rate: $200/night. Maximum meal allowance: $75/day."},
                    {"version": "2.0", "date": "2023-03-01", "status": "SUPERSEDED",
                     "content": "Business travel requires Manager approval for domestic, VP approval for international. Travel expenses must be submitted within 14 days. Maximum hotel rate: $250/night. Maximum meal allowance: $100/day."},
                    {"version": "3.0", "date": "2024-01-01", "status": "CURRENT",
                     "content": "Business travel requires Manager approval. International travel requires Director approval. Travel expenses must be submitted within 7 days. Maximum hotel rate: $300/night. Maximum meal allowance: $125/day. All flights must be economy class unless approved by VP."},
                ],
                "ground_truth_key": "current_travel_expense_deadline",
                "ground_truth_value": "7 days",
            },
            {
                "name": "Remote Work Policy",
                "versions": [
                    {"version": "1.0", "date": "2020-03-15", "status": "SUPERSEDED",
                     "content": "Due to COVID-19, all employees may work remotely until further notice. VPN required for all access. Weekly team check-ins mandatory."},
                    {"version": "2.0", "date": "2021-09-01", "status": "SUPERSEDED",
                     "content": "Hybrid work model: Employees must be in office minimum 3 days per week. Core hours: 10am-3pm. Remote work requests require manager approval."},
                    {"version": "3.0", "date": "2023-06-01", "status": "CURRENT",
                     "content": "Flexible work model: Employees may work remotely up to 4 days per week with manager approval. Fully remote positions available for approved roles. Core collaboration hours: 11am-2pm local time. Quarterly in-person team meetings required."},
                ],
                "ground_truth_key": "current_remote_days_allowed",
                "ground_truth_value": "4 days per week",
            },
            {
                "name": "PTO Policy",
                "versions": [
                    {"version": "1.0", "date": "2019-01-01", "status": "SUPERSEDED",
                     "content": "Annual PTO: 15 days for employees with <5 years tenure, 20 days for 5+ years. Sick leave: 10 days. PTO does not roll over."},
                    {"version": "2.0", "date": "2022-01-01", "status": "SUPERSEDED",
                     "content": "Annual PTO: 20 days for all employees. Sick leave: unlimited (reasonable use). Up to 5 days PTO may roll over."},
                    {"version": "3.0", "date": "2024-01-01", "status": "CURRENT",
                     "content": "Unlimited PTO policy. Minimum 15 days must be taken annually. Sick leave: unlimited. Mental health days: encouraged. Manager approval required for absences >5 consecutive days."},
                ],
                "ground_truth_key": "current_pto_policy",
                "ground_truth_value": "Unlimited PTO with minimum 15 days required",
            },
        ]

        for policy in policies:
            for ver in policy["versions"]:
                filename = f"{policy['name'].replace(' ', '_')}_{ver['version']}_{ver['status']}.txt"
                content = f"""{'='*60}
{policy['name']}
Version: {ver['version']}
Effective Date: {ver['date']}
Status: {ver['status']}
{'='*60}

{ver['content']}

---
Document Classification: INTERNAL
Last Updated: {ver['date']}
Next Review: {(datetime.strptime(ver['date'], '%Y-%m-%d') + timedelta(days=365)).strftime('%Y-%m-%d')}
Owner: Human Resources
"""
                with open(self.output_dir / filename, "w") as f:
                    f.write(content)

            self.ground_truth[policy["ground_truth_key"]] = policy["ground_truth_value"]

        print(f"  → {sum(len(p['versions']) for p in policies)} policy documents")

    def _generate_meeting_notes(self):
        """Generate meeting notes with conflicting/evolving information."""
        print("Generating meeting notes...")

        # Q4 Planning meetings with evolving decisions
        meetings = [
            {
                "date": "2024-10-15",
                "title": "Q4 Planning - Initial Discussion",
                "attendees": ["Sarah Chen (VP Product)", "Mike Johnson (VP Engineering)", "Lisa Park (CFO)"],
                "notes": """
## Q4 Budget Discussion

Initial proposal: $2.5M for Project Phoenix
- Engineering requests additional $500K for infrastructure
- Product wants $300K for user research
- Decision PENDING further analysis

Headcount:
- Proposal to hire 25 new engineers
- Lisa concerned about burn rate
- Will revisit next week

Launch date for Phoenix: Tentatively March 2025
""",
            },
            {
                "date": "2024-10-22",
                "title": "Q4 Planning - Budget Review",
                "attendees": ["Sarah Chen (VP Product)", "Mike Johnson (VP Engineering)", "Lisa Park (CFO)", "Tom Williams (CEO)"],
                "notes": """
## Q4 Budget - Updated

CEO approved revised budget: $2.8M for Project Phoenix
- Includes infrastructure ($500K)
- User research approved ($300K)
- FINAL DECISION

Headcount update:
- Approved: 20 new engineers (reduced from 25)
- Hiring to begin November 1
- Budget approved by finance

Launch date: CONFIRMED February 15, 2025 (moved up from March)
""",
            },
            {
                "date": "2024-11-05",
                "title": "Project Phoenix Status Update",
                "attendees": ["Sarah Chen (VP Product)", "Mike Johnson (VP Engineering)", "Rachel Kim (Project Lead)"],
                "notes": """
## Phoenix Status

Development on track. Beta launch: January 15, 2025.
Full launch: February 15, 2025 (confirmed)

Budget update:
- Spent to date: $1.2M
- Remaining: $1.6M
- On track

Risk: Third-party API integration delayed by 2 weeks
Mitigation: Team working overtime, may need $50K contingency

Headcount: 15 of 20 engineers hired. 5 positions still open.
""",
            },
        ]

        for meeting in meetings:
            filename = f"meeting_notes_{meeting['date']}.md"
            content = f"""# {meeting['title']}

**Date:** {meeting['date']}
**Attendees:** {', '.join(meeting['attendees'])}

---

{meeting['notes']}

---
_Notes taken by Executive Assistant_
_Distribution: Internal - Project Team Only_
"""
            with open(self.output_dir / filename, "w") as f:
                f.write(content)

        # Ground truth (latest decision)
        self.ground_truth["project_phoenix_budget"] = "$2.8M"
        self.ground_truth["project_phoenix_launch_date"] = "February 15, 2025"
        self.ground_truth["approved_engineering_headcount"] = 20

        print(f"  → {len(meetings)} meeting notes")

    def _generate_acronym_glossary(self):
        """Generate corporate acronym glossary."""
        print("Generating acronym glossary...")

        content = """# Corporate Acronym & Terminology Glossary

This document defines standard acronyms and terminology used within the organization.
Last Updated: 2024-11-01
Owner: Corporate Communications

---

"""
        for acronym, definition in sorted(ACRONYMS.items()):
            content += f"**{acronym}**: {definition}\n\n"

        # Add some company-specific ones
        company_acronyms = {
            "PHOENIX": "Platform for Hosted Operations, Enterprise Networking, and Integrated eXperience",
            "ATLAS": "Advanced Technology for Localized Account Solutions",
            "PRISM": "Product Roadmap and Innovation Strategy Management",
            "CORE": "Customer Operations and Revenue Excellence",
            "SPARK": "Strategic Planning and Resource Knowledge base",
        }

        content += "\n## Company-Specific Terminology\n\n"
        for acronym, definition in company_acronyms.items():
            content += f"**{acronym}**: {definition}\n\n"

        with open(self.output_dir / "corporate_glossary.md", "w") as f:
            f.write(content)

        self.ground_truth["TPS_meaning"] = ACRONYMS["TPS"]
        self.ground_truth["PHOENIX_meaning"] = company_acronyms["PHOENIX"]

        print(f"  → Glossary with {len(ACRONYMS) + len(company_acronyms)} terms")

    def _generate_procedures(self):
        """Generate cross-referenced procedure documents."""
        print("Generating procedure documents...")

        procedures = {
            "onboarding": """# Employee Onboarding Procedure
Document ID: PROC-HR-001
Version: 2.3
Effective: 2024-01-01

## Overview
This procedure outlines the steps for onboarding new employees.

## Prerequisites
- Signed offer letter
- Completed background check (see PROC-HR-015)
- IT equipment request submitted (see PROC-IT-003)

## Day 1 Checklist
1. Badge activation (Security, Building A lobby)
2. IT setup (see PROC-IT-007 for details)
3. Benefits enrollment (due within 30 days - see PROC-HR-008)
4. Complete required training (see Training Matrix, DOC-HR-042)

## Required Training
All new hires must complete within 30 days:
- Security Awareness (2 hours) - see PROC-SEC-001
- Code of Conduct (1 hour)
- Anti-harassment (1 hour)
- Department-specific training (varies)

## References
- PROC-HR-015: Background Check Procedure
- PROC-IT-003: Equipment Request
- PROC-IT-007: System Access Setup
- PROC-HR-008: Benefits Enrollment
- PROC-SEC-001: Security Training Requirements
- DOC-HR-042: Training Matrix
""",
            "expense": """# Expense Reimbursement Procedure
Document ID: PROC-FIN-002
Version: 3.1
Effective: 2024-06-01

## Overview
This procedure covers submission and approval of expense reports.

## Expense Limits (per Travel Policy v3.0)
- Meals: $125/day maximum
- Hotels: $300/night maximum (see exceptions in PROC-FIN-002a)
- Flights: Economy class (business class requires VP approval)

## Submission Process
1. Submit via Concur within 7 days of expense
2. Attach itemized receipts for all expenses >$25
3. Manager approval required for all submissions
4. Director approval required for expenses >$1,000
5. VP approval required for expenses >$5,000

## Payment Timeline
- Approved expenses paid within 5 business days
- Direct deposit to payroll account
- Questions: expense-help@company.com

## References
- Travel Policy v3.0
- PROC-FIN-002a: Hotel Rate Exceptions
- PROC-FIN-010: Corporate Card Usage
""",
            "security_incident": """# Security Incident Response Procedure
Document ID: PROC-SEC-005
Version: 4.0
Effective: 2024-03-15
Classification: INTERNAL - SENSITIVE

## Overview
This procedure must be followed for ALL security incidents.

## Incident Classification
- P1 (Critical): Data breach, system compromise - notify within 15 minutes
- P2 (High): Attempted breach, suspicious activity - notify within 1 hour
- P3 (Medium): Policy violation, minor issue - notify within 4 hours
- P4 (Low): Informational - include in weekly report

## Notification Chain
1. Security Operations Center: security-ops@company.com, +1-555-SEC-OPS1
2. CISO (for P1/P2): via PagerDuty
3. Legal (for P1): legal-urgent@company.com
4. CEO (for P1 data breach): via Executive Assistant

## Response Steps
1. CONTAIN: Isolate affected systems (see PROC-SEC-006)
2. ASSESS: Determine scope and impact
3. NOTIFY: Follow notification chain above
4. REMEDIATE: Execute remediation plan
5. DOCUMENT: Complete incident report (FORM-SEC-001)
6. REVIEW: Post-incident review within 5 business days

## References
- PROC-SEC-006: System Isolation Procedure
- FORM-SEC-001: Incident Report Template
- PROC-SEC-010: Forensic Investigation
- Legal Hold Procedure (PROC-LEG-003)
""",
        }

        for name, content in procedures.items():
            with open(self.output_dir / f"procedure_{name}.md", "w") as f:
                f.write(content)

        self.ground_truth["expense_submission_deadline"] = "7 days"
        self.ground_truth["p1_incident_notification_time"] = "15 minutes"
        self.ground_truth["new_hire_training_deadline"] = "30 days"

        print(f"  → {len(procedures)} procedure documents")

    def _generate_quarterly_reports(self):
        """Generate quarterly business reports with financial data."""
        print("Generating quarterly reports...")

        quarters = [
            {"quarter": "Q1 2024", "revenue": 45_200_000, "expenses": 38_500_000, "headcount": 4850},
            {"quarter": "Q2 2024", "revenue": 48_700_000, "expenses": 40_200_000, "headcount": 4920},
            {"quarter": "Q3 2024", "revenue": 52_100_000, "expenses": 42_800_000, "headcount": 5050},
            {"quarter": "Q4 2024", "revenue": 58_400_000, "expenses": 45_100_000, "headcount": 5200},
        ]

        for q in quarters:
            profit = q["revenue"] - q["expenses"]
            margin = (profit / q["revenue"]) * 100

            content = f"""# Quarterly Business Report - {q['quarter']}

## Executive Summary
This report summarizes financial and operational performance for {q['quarter']}.

## Financial Highlights

| Metric | Amount |
|--------|--------|
| Revenue | ${q['revenue']:,} |
| Operating Expenses | ${q['expenses']:,} |
| Operating Profit | ${profit:,} |
| Profit Margin | {margin:.1f}% |

## Headcount
- Total Employees: {q['headcount']}
- Net Change: +{q['headcount'] - quarters[quarters.index(q)-1]['headcount'] if quarters.index(q) > 0 else 'N/A'}

## Key Achievements
- Launched Project Atlas in APAC region
- Achieved SOC 2 Type II certification
- Customer NPS increased to 72 (+5 points)

## Challenges
- Increased competition in enterprise segment
- Supply chain delays affecting hardware deployment
- Engineering hiring slower than planned

## Outlook
Management expects continued growth in {q['quarter'].replace('Q', 'Q' + str((int(q['quarter'][1])) % 4 + 1) if q['quarter'][1] != '4' else 'Q1 ' + str(int(q['quarter'][-4:]) + 1))}.

---
Prepared by: Finance Team
Distribution: Executive Leadership, Board of Directors
Classification: CONFIDENTIAL
"""
            filename = f"quarterly_report_{q['quarter'].replace(' ', '_')}.md"
            with open(self.output_dir / filename, "w") as f:
                f.write(content)

        self.ground_truth["q4_2024_revenue"] = "$58,400,000"
        self.ground_truth["q4_2024_headcount"] = 5200
        self.ground_truth["total_2024_revenue"] = f"${sum(q['revenue'] for q in quarters):,}"

        print(f"  → {len(quarters)} quarterly reports")

    def _save_ground_truth(self):
        """Save ground truth answers for testing."""
        with open(self.output_dir / "ground_truth.json", "w") as f:
            json.dump(self.ground_truth, f, indent=2)

        # Also create a test queries file
        test_queries = [
            {
                "query": "How many employees work in Engineering?",
                "expected_answer": str(self.ground_truth.get("engineering_headcount", "")),
                "difficulty": "easy",
                "requires": ["employee_directory.csv"],
            },
            {
                "query": "What is the average salary for Engineering employees?",
                "expected_answer": f"${self.ground_truth.get('avg_engineering_salary', 0):,}",
                "difficulty": "hard",
                "requires": ["employee_directory.csv", "compensation_data_confidential.csv"],
                "notes": "Requires JOIN between employee directory and compensation data",
            },
            {
                "query": "Who is the highest paid employee and what is their total compensation?",
                "expected_answer": f"{self.ground_truth.get('highest_paid_employee', '')} - ${self.ground_truth.get('highest_compensation', 0):,}",
                "difficulty": "hard",
                "requires": ["employee_directory.csv", "compensation_data_confidential.csv"],
            },
            {
                "query": "Who does the CEO report to?",
                "expected_answer": "No one (CEO is top of hierarchy)",
                "difficulty": "medium",
                "requires": ["org_hierarchy.json"],
            },
            {
                "query": "How many direct reports does the CEO have?",
                "expected_answer": str(self.ground_truth.get("ceo_direct_reports", "")),
                "difficulty": "medium",
                "requires": ["org_hierarchy.json"],
            },
            {
                "query": "What is the approved budget for Project Phoenix?",
                "expected_answer": self.ground_truth.get("project_phoenix_budget", ""),
                "difficulty": "hard",
                "requires": ["meeting_notes_2024-10-22.md"],
                "notes": "Multiple meetings discuss budget - must find FINAL decision",
            },
            {
                "query": "When is Project Phoenix launching?",
                "expected_answer": self.ground_truth.get("project_phoenix_launch_date", ""),
                "difficulty": "hard",
                "requires": ["meeting_notes_2024-10-22.md", "meeting_notes_2024-11-05.md"],
                "notes": "Date changed between meetings - must find latest",
            },
            {
                "query": "How many days do I have to submit travel expenses?",
                "expected_answer": self.ground_truth.get("current_travel_expense_deadline", ""),
                "difficulty": "hard",
                "requires": ["Travel_Policy_3.0_CURRENT.txt"],
                "notes": "Multiple versions exist - must find CURRENT policy",
            },
            {
                "query": "What is the current PTO policy?",
                "expected_answer": self.ground_truth.get("current_pto_policy", ""),
                "difficulty": "hard",
                "requires": ["PTO_Policy_3.0_CURRENT.txt"],
                "notes": "Policy changed from limited to unlimited",
            },
            {
                "query": "What does TPS stand for?",
                "expected_answer": self.ground_truth.get("TPS_meaning", ""),
                "difficulty": "medium",
                "requires": ["corporate_glossary.md"],
            },
            {
                "query": "What does PHOENIX stand for in company terminology?",
                "expected_answer": self.ground_truth.get("PHOENIX_meaning", ""),
                "difficulty": "medium",
                "requires": ["corporate_glossary.md"],
            },
            {
                "query": "How quickly must I report a P1 security incident?",
                "expected_answer": self.ground_truth.get("p1_incident_notification_time", ""),
                "difficulty": "medium",
                "requires": ["procedure_security_incident.md"],
            },
            {
                "query": "What training must new employees complete and by when?",
                "expected_answer": f"Security Awareness, Code of Conduct, Anti-harassment within {self.ground_truth.get('new_hire_training_deadline', '')}",
                "difficulty": "hard",
                "requires": ["procedure_onboarding.md"],
                "notes": "Requires understanding cross-references to other procedures",
            },
            {
                "query": "What was the total company revenue in 2024?",
                "expected_answer": self.ground_truth.get("total_2024_revenue", ""),
                "difficulty": "hard",
                "requires": ["quarterly_report_Q1_2024.md", "quarterly_report_Q2_2024.md", "quarterly_report_Q3_2024.md", "quarterly_report_Q4_2024.md"],
                "notes": "Requires aggregating data from 4 separate quarterly reports",
            },
            {
                "query": "How many employees work remotely?",
                "expected_answer": str(self.ground_truth.get("remote_employees", "")),
                "difficulty": "medium",
                "requires": ["employee_directory.csv"],
            },
        ]

        with open(self.output_dir / "test_queries.json", "w") as f:
            json.dump(test_queries, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Generate enterprise documents for RAG testing")
    parser.add_argument("output_dir", help="Directory to write generated documents")
    parser.add_argument("--employees", type=int, default=5000, help="Number of employees to generate (default: 5000)")
    args = parser.parse_args()

    generator = EnterpriseDataGenerator(
        output_dir=Path(args.output_dir),
        num_employees=args.employees,
    )
    generator.generate_all()


if __name__ == "__main__":
    main()
