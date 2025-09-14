from fpdf import FPDF

def generate_report(target, results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt=f"Threat Scan Report for {target}", ln=True, align="C")
    pdf.ln(10)

    for res in results:
        pdf.cell(200, 10, txt=f"Port: {res['port']} | Service: {res['service']} {res['version']}", ln=True)
        if res["vulnerabilities"]:
            pdf.multi_cell(200, 10, txt="Vulnerabilities: " + ", ".join(res["vulnerabilities"]))
        else:
            pdf.cell(200, 10, txt="No known CVEs found.", ln=True)
        pdf.ln(5)

    pdf.output("report.pdf")
  
