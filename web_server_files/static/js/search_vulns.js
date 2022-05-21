
var curVulnData = {};
var ignoreGeneralCpeVulns = false;
var iconUnsorted = '<i class="fa-solid fa-sort"></i>';
var iconSortDesc = '<i class="fa-solid fa-sort-down"></i>';
var iconSortAsc = '<i class="fa-solid fa-sort-up"></i>';
var curSortColIdx = 1, curSortColAsc = false;
var showAsButtonsHTML = `<div class="row mt-3 justify-content-center align-items-center"><div class="col-6 text-center justify-content-center align-items-center"><button type="button" class="btn btn-info" name="copyCSVButton" id="copyCSVButton" onclick="copyToClipboardCSV()"><i style="font-size: 1rem" class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (CSV)</button></div><div class="col-6 text-center justify-content-center align-items-center"><button type="button" class="btn btn-info" name="copyMarkdownTableButton" id="copyMarkdownTableButton" onclick="copyToClipboardMarkdownTable()"><i style="font-size: 1rem" class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (Markdown Table)</button></div></div>`;

function htmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>\&"']/g, function (i) {
        return '&#' + i.charCodeAt(0) + ';';
    });
}

function getCurrentVulnsSorted() {
    var vulns = Object.values(Object.values(curVulnData)[0]);
    if (curSortColIdx == 0) {  // CVE-ID
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            }).reverse();

        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln1.cvss) - parseFloat(vuln2.cvss);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln2.cvss) - parseFloat(vuln1.cvss);
            });
        }
    }
    else if (curSortColIdx == 3) {  // Exploits
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                exploits1 = vuln1.exploits || [];
                exploits2 = vuln2.exploits || [];
                return parseInt(exploits1.length) - parseInt(exploits2.length);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                exploits1 = vuln1.exploits || [];
                exploits2 = vuln2.exploits || [];
                return parseInt(exploits2.length) - parseInt(exploits1.length);
            });
        }
    }
}

function createVulnsHtml() {
    var sortIconCVEID = iconUnsorted, sortFunctionCVEID = "reorderVulns(0, false)";
    var sortIconCVSS = iconUnsorted, sortFunctionCVSS = "reorderVulns(1, false)";
    var sortIconExploits = iconUnsorted, sortFunctionExploits = "reorderVulns(3, false)";

    // retrieve and sort vulns
    var vulns = getCurrentVulnsSorted();
    if (curSortColIdx == 0) {  // CVE-ID
        if (curSortColAsc) {
            sortIconCVEID = iconSortAsc;
            sortFunctionCVEID = "reorderVulns(0, false)";
        }
        else {
            sortIconCVEID = iconSortDesc;
            sortFunctionCVEID = "reorderVulns(0, true)";
        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            sortIconCVSS = iconSortAsc;
            sortFunctionCVSS = "reorderVulns(1, false)";
        }
        else {
            sortIconCVSS = iconSortDesc;
            sortFunctionCVSS = "reorderVulns(1, true)";
        }
    }
    else if (curSortColIdx == 3) {  // Exploits
        if (curSortColAsc) {
            sortIconExploits = iconSortAsc;
            sortFunctionExploits = "reorderVulns(3, false)";
        }
        else {
            sortIconExploits = iconSortDesc;
            sortFunctionExploits = "reorderVulns(3, true)";
        }
    }

    vulns_html = '<table class="table table-sm table-rounded table-striped">';
    vulns_html += '<thead class="bg-darker">';
    vulns_html += '<tr>'
    vulns_html += `<th onclick="${sortFunctionCVEID}" style="white-space: nowrap;">CVE-ID&nbsp;&nbsp;${sortIconCVEID}</th>`;
    vulns_html += `<th onclick="${sortFunctionCVSS}" style="white-space: nowrap;">CVSS&nbsp;&nbsp;${sortIconCVSS}</th>`;
    vulns_html += '<th>Description</th>'
    vulns_html += `<th onclick="${sortFunctionExploits}" style="white-space: nowrap;">Exploit&nbsp;&nbsp;${sortIconExploits}</th>`;
    vulns_html += "</tr></thead>";
    vulns_html += "<tbody>";
    vulns_html += "<tr></<tr>";  // make striping start with white
    var exploits, cvss;

    for (var i = 0; i < vulns.length; i++) {
        vulns_html += `<tr>`;
        vulns_html += `<td class="text-nowrap pr-2"><a href="${htmlEntities(vulns[i]["href"])}" target="_blank" style="color: inherit;">${vulns[i]["id"]}&nbsp;&nbsp;<i class="fa-solid fa-up-right-from-square" style="font-size: 0.92rem"></i></a></td>`;

        cvss = parseFloat(vulns[i].cvss);
        if (cvss >= 9.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-critical text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 9.0 && cvss >= 7.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-high text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 7.0 && cvss >= 4.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-medium text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 4.0 && cvss >= 0.1)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-low text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;

        vulns_html += `<td>${htmlEntities(vulns[i]["description"])}</td>`;

        exploits = [];
        if (vulns[i].exploits !== undefined) {
            for (var j = 0; j < vulns[i].exploits.length; j++)
                exploits.push(`<a href="${vulns[i].exploits[j]}" target="_blank" style="color: inherit;">${htmlEntities(vulns[i].exploits[j])}</a>`);
        }
        vulns_html += `<td class="text-nowrap">${exploits.join("<br>")}</td>`;

        vulns_html += "</tr>"
    }
    vulns_html += "</tbody></table>";
    return vulns_html;
}

function createVulnsMarkDownTable() {
    var vulns = getCurrentVulnsSorted();
    var vulns_md = "";
    var has_exploits = false;

    for (var i = 0; i < vulns.length; i++) {
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            has_exploits = true;
            break
        }
    }

    if (has_exploits) {
        vulns_md = '|CVE|CVSS|Description|Exploits|\n';
        vulns_md += '|:---:|:---:|:---|:---|\n';
    }
    else {
        vulns_md = '|CVE|CVSS|Description|\n';
        vulns_md += '|:---:|:---:|:---|\n';
    }

    for (var i = 0; i < vulns.length; i++) {
        vulns_md += `|${vulns[i]["id"].replaceAll('-', '&#8209;')}|${vulns[i]["cvss"]}&nbsp;(v${vulns[i]["cvss_ver"]})|`;
        vulns_md += `${htmlEntities(vulns[i]["description"]).replaceAll('|', '&#124;')}|`;

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0)
            vulns_md += `${vulns[i].exploits.join("<br>")}|`;
        else if (has_exploits)
            vulns_md += "|";

        vulns_md += '\n'
    }

    return vulns_md;
}

function createVulnsCSV() {
    var vulns = getCurrentVulnsSorted();
    var vulns_csv = "";
    var has_exploits = false;

    for (var i = 0; i < vulns.length; i++) {
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            has_exploits = true;
            break
        }
    }

    if (has_exploits)
        vulns_csv = 'CVE,CVSS,Description,Exploits\n';
    else
        vulns_csv = 'CVE,CVSS,Description\n';

    for (var i = 0; i < vulns.length; i++) {
        vulns_csv += `${vulns[i]["id"]},${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]}),`;
        vulns_csv += `"${vulns[i]["description"].replaceAll('"', '""')}"`;

        if (has_exploits)
            vulns_csv += ",";

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0)
            vulns_csv += `"${vulns[i].exploits.join(", ")}"`;
        vulns_csv += '\n'
    }

    return vulns_csv;
}


function searchVulns() {
    var query = $('#query').val();
    var queryEnc = encodeURIComponent(query);
    var url_query = "query=" + queryEnc;
    var new_url = window.location.pathname + '?query=' + queryEnc;

    if (ignoreGeneralCpeVulns) {
        url_query += "&ignore-general-cpe-vulns=true";
        new_url += '&general-vulns=false';
    }

    history.pushState({}, null, new_url);  // update URL
    $("#searchVulnsButton").attr("disabled", true);
    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curSortColIdx = 1;
    curSortColAsc = false;
    curVulnData = {};

    $.get({
        url: "/search_vulns",
        data: url_query,
        success: function (vulns) {
            var vulns_html = "";
            if (Object.keys(vulns[query]).length) {
                if (typeof vulns[query] !== "object")
                    vulns_html = `<h5 class="text-danger text-center">${htmlEntities(vulns[query])}</h5>`;
                else {
                    curVulnData = vulns;
                    vulns_html = createVulnsHtml(1, false);
                    vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
                    vulns_html += showAsButtonsHTML;
                }
            } else {
                vulns_html = `<h5 class="text-center">No known vulnerabilities could be found for '${htmlEntities(query)}'</h5>`;
            }
            $("#vulns").html(vulns_html);
            $("#searchVulnsButton").removeAttr("disabled");
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;

            $("#vulns").html(`<h5 class="text-danger text-center">${htmlEntities(errorMsg)}</h5>`);
            $("#searchVulnsButton").removeAttr("disabled");
        }
    })
}

function reorderVulns(sortColumnIdx, asc) {
    curSortColIdx = sortColumnIdx;
    curSortColAsc = asc;
    vulns_html = createVulnsHtml(sortColumnIdx, asc);
    vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
    vulns_html += showAsButtonsHTML;
    $("#vulns").html(vulns_html);
}

function ignoreGeneralVulnsToggle() {
    ignoreGeneralCpeVulns = !ignoreGeneralCpeVulns;
    $("#vulns").html('');
    curVulnData = {};
}

function copyToClipboardMarkdownTable() {
    navigator.clipboard.writeText(createVulnsMarkDownTable());
    $("#copyMarkdownTableButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard-check"></i>&nbsp;&nbsp;Copied Markdown Table to Clipboard');
    $("#copyMarkdownTableButton").attr('class', 'btn btn-success');
}

function copyToClipboardCSV() {
    navigator.clipboard.writeText(createVulnsCSV());
    $("#copyCSVButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard-check"></i>&nbsp;&nbsp;Copied CSV to Clipboard');
    $("#copyCSVButton").attr('class', 'btn btn-success');
}

function init() {
    if (location.search !== '' && location.search !== '?') {
        var url = new URL(document.location.href);
        var params = new URLSearchParams(url.search);
        var init_query = params.get('query');
        if (init_query !== null)
            $('#query').val(htmlEntities(init_query));

        var show_general_vulns = params.get('general-vulns');
        if (String(show_general_vulns).toLowerCase() === "false")
            $('#toggleIgnoreGeneralCpeVulns').click();

        if (init_query !== null)
            $("#searchVulnsButton").click();
    }
}

// enables the user to press return on the query text field to make the query
$("#query").keypress(function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == "13" && $("#searchVulnsButton").attr("disabled") === undefined)
        $("#searchVulnsButton").click();
});

// check for existing query in URL
init();

// activate tooltips
$(document).ready(function () {
    $("body").tooltip({ selector: '[data-toggle=tooltip]' });
});
