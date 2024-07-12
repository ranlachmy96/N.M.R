const fs = require('fs');
const path = require('path');
const dataPath = path.join(__dirname, '../data/data.json');

let reports = require(dataPath).reports;

const saveDataToFile = () => {
    const dataToWrite = { reports };
    fs.writeFileSync(dataPath, JSON.stringify(dataToWrite, null, 2));
};

//get all reports
const findReports = () => {
    return reports;
};

//get an report by ID
const retrieveReport = (id) => {
    return reports.find((report) => report.id === id);
};

//Create a new report
const createReport = (report) => {
    reports.push(report);
    saveDataToFile();
    return report;
}

//Update an report by ID
const updateReport = (id,updatedReport) => {
    const index = reports.findIndex((report) => report.id === id);
    if (index !== -1){
        reports[index] = { ...reports[index], ...updatedReport };
        saveDataToFile();
        return reports[index];
    }
}

//Delete an report by ID
const deleteReport = (id) => {
        const index = reports.findIndex((report) => report.id === id);
        if (index !== -1) {
            const deletedReport = reports.splice(index, 1)[0];
            saveDataToFile();
            return deletedReport;
        }
}

// module.exports = { getReports , getReport , postReport , putReport , deleteReport };

module.exports = { findReports, retrieveReport, createReport, updateReport, deleteReport }