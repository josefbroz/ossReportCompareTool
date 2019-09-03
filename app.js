
const fs = require('fs')

// process CLI parameters using yargs
const yargs = require('yargs')
const chalk = require('chalk')

yargs
    .command({
        command: 'compare',
        describe: 'Compare two OSS index scan reports, write new CVS to output.json file. ',
        builder: {
            oldReportFile: {
                describe: 'Old OSS Index scan report file path.',
                demandOption: true,
                type: 'string'
            },
            newReportFile: {
                describe: 'New OSS Index scan report file path.',
                demandOption: true,
                type: 'string'
            },
        },
        handler: function (argv) {
            console.log('Comparing OSS scan reports, old report path:' + argv.oldReportFile + ', new report path:' + argv.newReportFile)
            compare(argv)
        },
        help: 'h'
    }).parse();


function compare(argv) {

    // read old version file
    const oldVersionReport = parseOssIndexReport(argv.oldReportFile)
    // red new version file
    const newVersionReport = parseOssIndexReport(argv.newReportFile)
    // search for new CVEs
    let libWithNewCve = { newVulnerabilities: [] }
    Object.entries(newVersionReport.vulnerable).forEach(newReportVulnerableLibrary => {
        let oldReportVulnerableLibrary = findOldReportLibrary(newReportVulnerableLibrary[0], oldVersionReport)
        //compare CVEs of old and new report libraries
        console.log("Processing " +chalk.red(newReportVulnerableLibrary[0]))
        if (oldReportVulnerableLibrary !== undefined) {
            // process also CVEs from old report vulnerable libraries
            newCves = newReportVulnerableLibrary[1].vulnerabilities.filter(cve => isCveNew(cve, oldReportVulnerableLibrary[1].vulnerabilities))
            console.log("New CVEs found:")
            console.log(newCves)
            if (newCves.length !== 0) {
                newReportVulnerableLibrary[1].vulnerabilities = newCves
                libWithNewCve.newVulnerabilities.push(newReportVulnerableLibrary)
            }
        } else {
            console.log("New CVEs found:")
            console.log(newReportVulnerableLibrary[1].vulnerabilities)
            libWithNewCve.newVulnerabilities.push(newReportVulnerableLibrary)
        }
    });
    // create and write merge output
    fs.writeFileSync("output.json", JSON.stringify(libWithNewCve))
    // TODO search for removed CVEs (if any)

}

function parseOssIndexReport(reportPath) {
    const dataBytes = fs.readFileSync(reportPath)
    return JSON.parse(dataBytes.toString())
}

function findOldReportLibrary(oldReportLibraryName, oldVersionReport) {
    return Object.entries(oldVersionReport.vulnerable).find(lib => lib[0] === oldReportLibraryName)
}

function isCveNew(cve, oldCves) {
    return oldCves.find(oldCve => oldCve.id === cve.id) === undefined
}