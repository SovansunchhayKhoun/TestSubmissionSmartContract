// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

contract TestSubmissionSystem {
    // Struct to store Decentralized Identifier (DID) information
    struct DID {
        string identifier; // Unique identifier for the DID
        address owner; // Address of the owner of this DID
        uint256 createdAt; // Timestamp when the DID was created
    }

    // Struct to store metadata about a user
    struct StudentMetaData {
        string name; // User's name
        string email; // User's email address
        string profilePicture; // URL to the user's profile picture
        uint256 totalTestsSubmitted; // Total number of tests the user has submitted
        uint256 lastTestScore; // Last test score received by the user
    }

    // Struct to store metadata about a user
    struct TeacherMetaData {
        string name; // User's name
        string email; // User's email address
        string profilePicture; // URL to the user's profile picture
        int256 totalTestCreated;
    }

    // Struct to define a question in a test
    struct Question {
        string text; // Question text
        string[4] answers; // Four possible answers to the question
        uint8 correctAnswerIndex; // Index of the correct answer (0-3)
    }

    // Struct to define a test
    struct Test {
        string title; // Title of the test
        Question[] questions; // Array of questions in the test
        uint256 maxScore; // Maximum score a participant can achieve
        bool exists; // Boolean to check if the test exists
    }

    // Struct to store details of a test submission
    struct TestSubmission {
        uint256 testId; // ID of the test being submitted
        uint8[] answers; // Array of answers submitted by the user
        bytes32 answerHash; // Answer hash
        uint256 grade; // Grade achieved by the user
        bytes32 gradeHash; // grade hash
        uint256 submissionTime; // Timestamp of the submission
        bool graded; // Whether the test has been graded
    }

    // Struct to represent issued credentials for roles
    struct Credential {
        address issuer; // Address of the role issuer
        string role; // Role issued to the user
        uint256 issueAt; // Timestamp of when the role was issued
        bytes32 hashes; // Hash to verify credential issuance
    }

    // Mappings to store data
    mapping(address => DID) private dids; // Mapping to store DID for each address
    mapping(address => string) private roles; // Mapping to store role for each user
    mapping(address => string[]) private roleHistory; // Role history for each user
    mapping(address => StudentMetaData) private studentMetadatas; // Metadata for each user
    mapping(address => TeacherMetaData) private teacherMetadas; // Metadata for each user
    mapping(address => Credential[]) private credentials; // Credentials issued to each user
    mapping(address => TestSubmission[]) private testSubmissions; // Test submissions for each user
    mapping(uint256 => Test) private tests; // Mapping of test ID to Test struct
    mapping(address => mapping(uint256 => bool)) private hasTakenTest; // Mapping to track whether a student has already taken a test
    uint256 private nextTestId; // Auto-incrementing test ID for new tests

    // Constructor to initialize the contract
    constructor() {
        roles[msg.sender] = "government"; // Assign "government" role to the contract deployer
        roleHistory[msg.sender].push("government"); // Add "government" to role history
    }

    // Events to log actions
    event DIDCreated(address indexed owner, string identifier); // When a DID is created
    event SetStudentMetaData(
        address indexed owner,
        string name,
        string email,
        string profilePicture
    );
    event SetTeacherMetaData(
        address indexed owner,
        string name,
        string email,
        string profilePicture,
        int256 totalTestCreated
    );
    event RoleAssigned(address indexed user, string role); // When a role is assigned
    event RoleIssued(
        address indexed user,
        address receiver,
        string role,
        bytes32 hash
    ); // When a role is issued
    event TestCreated(uint256 indexed testId, string title, uint256 maxScore); // When a test is created
    event TestSubmitted(address indexed user, uint256 testId, uint256 grade); // When a test is submitted

    // Modifiers to enforce role-based access control
    modifier onlyGovernment() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) ==
                keccak256("government"),
            "Only government can perform this action"
        );
        _;
    }

    modifier onlyTeacher() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) ==
                keccak256("teacher"),
            "Only teacher can perform this action"
        );
        _;
    }

    modifier onlyStudent() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) ==
                keccak256("student"),
            "Only student can perform this action"
        );
        _;
    }

    modifier onlyGovernmentOrTeacher() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) ==
                keccak256("teacher") ||
                keccak256(abi.encodePacked(roles[msg.sender])) ==
                keccak256("government"),
            "Only admins can perform this action"
        );
        _;
    }

    // Function to assign roles (teacher or student)
    function assignRole(address _user, string memory _role)
        public
        onlyGovernment
    {
        require(dids[msg.sender].owner != address(0), "Issuer must have a DID"); // Ensure issuer has a DID
        require(bytes(_role).length > 0, "Role cannot be empty"); // Ensure the role is not empty

        // Validate role names
        require(
            keccak256(abi.encodePacked(_role)) == keccak256("teacher") ||
                keccak256(abi.encodePacked(_role)) == keccak256("student"),
            "Invalid role"
        );

        roles[_user] = _role; // Assign the role
        roleHistory[_user].push(_role); // Add the role to user's role history
        emit RoleAssigned(_user, _role); // Emit the RoleAssigned event
    }

    // Function for super admin to issue roles
    function issueRole(address _user, string memory _role)
        public
        onlyGovernment
    {
        require(dids[msg.sender].owner != address(0), "Issuer must have a DID");
        require(bytes(_role).length > 0, "Role cannot be empty");

        bytes32 roleHash = keccak256(
            abi.encodePacked(msg.sender, _user, _role, block.timestamp)
        );

        credentials[_user].push(
            Credential(msg.sender, _role, block.timestamp, roleHash)
        );

        roleHistory[_user].push(_role);

        emit RoleIssued(msg.sender, _user, _role, roleHash);
    }

    // Function to create a DID for a user
    function createDID(string memory _identifier) public {
        require(bytes(_identifier).length > 0, "Identifier cannot be empty");
        require(dids[msg.sender].owner == address(0), "DID already exists");
        dids[msg.sender] = DID(_identifier, msg.sender, block.timestamp);
        emit DIDCreated(msg.sender, _identifier);
    }

    function getDID() public view returns (string memory) {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );

        return dids[msg.sender].identifier;
    }

    function setTeacherMetadata(
        string memory name,
        string memory email,
        string memory profilePicture
    ) public onlyTeacher {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(email).length > 0, "Email cannot be empty");
        require(
            bytes(profilePicture).length > 0,
            "Profile picture cannot be empty"
        );

        teacherMetadas[msg.sender] = TeacherMetaData(
            name,
            email,
            profilePicture,
            0
        );

        emit SetTeacherMetaData(msg.sender, name, email, profilePicture, 0);
    }

    function setStudentMetadata(
        string memory name,
        string memory email,
        string memory profilePicture
    ) public onlyStudent {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(email).length > 0, "Email cannot be empty");
        require(
            bytes(profilePicture).length > 0,
            "Profile picture cannot be empty"
        );

        studentMetadatas[msg.sender] = StudentMetaData(
            name,
            email,
            profilePicture,
            0,
            0
        );

        emit SetStudentMetaData(msg.sender, name, email, profilePicture);
    }

    function getStudentMetadata()
        public
        view
        onlyStudent
        returns (StudentMetaData memory)
    {
        require(dids[msg.sender].owner != address(0), "Data does not exist");
        return studentMetadatas[msg.sender];
    }

    function getTeacherMetadata()
        public
        view
        onlyTeacher
        returns (TeacherMetaData memory)
    {
        require(dids[msg.sender].owner != address(0), "Data does not exist");
        return teacherMetadas[msg.sender];
    }

    function getRole() public view returns (string[] memory) {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );
        require(roleHistory[msg.sender].length > 0, "No roles assigned yet");
        return roleHistory[msg.sender];
    }

    function verifyRole(
        address user,
        string memory role,
        address issuerAddress
    ) public view returns (bool) {
        require(
            dids[user].owner != address(0),
            "No DID found for this address"
        );
        require(
            bytes(roles[user]).length > 0,
            "User does not have any assigned roles"
        );

        bool roleMatches = keccak256(abi.encodePacked(roles[user])) ==
            keccak256(abi.encodePacked(role));
        bool issuerMatches = false;

        // Check the role issuer and the hash in the user's credentials
        for (uint256 i = 0; i < credentials[user].length; i++) {
            if (
                credentials[user][i].issuer == issuerAddress &&
                keccak256(abi.encodePacked(credentials[user][i].role)) ==
                keccak256(abi.encodePacked(role))
            ) {
                issuerMatches = true;
                break;
            }
        }

        return roleMatches && issuerMatches;
    }

    // Function for admin to create a test
    function createTest(string memory title, Question[] memory questions)
        public
        onlyTeacher
    {
        require(bytes(title).length > 0, "Test title cannot be empty");
        require(questions.length > 0, "Questions are required");

        uint256 maxScore = questions.length; // Maximum score equals the number of questions

        Test storage newTest = tests[nextTestId]; // Create a new test
        newTest.title = title;
        newTest.exists = true;
        newTest.maxScore = maxScore;

        // Add questions to the test
        for (uint256 i = 0; i < questions.length; i++) {
            require(
                bytes(questions[i].text).length > 0,
                "Question text cannot be empty"
            );
            require(
                questions[i].correctAnswerIndex < 4,
                "Invalid correct answer index"
            );
            newTest.questions.push(questions[i]);
        }

        teacherMetadas[msg.sender].totalTestCreated++; // Update teacher totalTestCreated metadata

        emit TestCreated(nextTestId, title, maxScore); // Emit TestCreated event
        nextTestId++; // Increment test ID for the next test
    }

    // Function to allow students to view test questions without revealing answers
    function getTestQuestions(uint256 testId)
        public
        view
        onlyGovernmentOrTeacher
        returns (Question[] memory)
    {
        require(tests[testId].exists, "Test does not exist");

        uint256 numQuestions = tests[testId].questions.length;
        Question[] memory questionsToView = new Question[](numQuestions);

        for (uint256 i = 0; i < numQuestions; i++) {
            // Return only the text and the possible answers, but not the correct answer index
            questionsToView[i] = Question({
                text: tests[testId].questions[i].text,
                answers: tests[testId].questions[i].answers,
                correctAnswerIndex: 255 // Placeholder value to ensure privacy (since it's hidden)
            });
        }

        return questionsToView;
    }

    // Students submit test answers
    function submitTest(uint256 testId, uint8[] memory answers)
        public
        onlyStudent
    {
        require(tests[testId].exists, "Test does not exist");
        require(
            answers.length == tests[testId].questions.length,
            "Answers count mismatch"
        );
        require(
            !hasTakenTest[msg.sender][testId],
            "You have already taken this test"
        ); // Ensure only one test submission

        // Hash the submitted answers
        bytes32 answersHash = keccak256(
            abi.encodePacked(msg.sender, testId, answers)
        );

        uint256 grade = 0;
        for (uint256 i = 0; i < answers.length; i++) {
            if (answers[i] == tests[testId].questions[i].correctAnswerIndex) {
                grade++;
            }
        }

        // Hash the grade
        bytes32 gradeHash = keccak256(
            abi.encodePacked(msg.sender, testId, grade)
        );

        testSubmissions[msg.sender].push(
            TestSubmission({
                testId: testId, // ID of the test being submitted
                answers: answers, // Array of answers submitted by the user
                answerHash: answersHash, // Answer hash
                grade: grade, // Grade achieved by the user
                gradeHash: gradeHash, // grade hash
                submissionTime: block.timestamp, // Timestamp of the submission
                graded: true // Whether the test has been graded
            })
        );

        studentMetadatas[msg.sender].totalTestsSubmitted++;
        studentMetadatas[msg.sender].lastTestScore = grade;

        // Mark test as taken
        hasTakenTest[msg.sender][testId] = true;

        emit TestSubmitted(msg.sender, testId, grade);
    }

    // Students view their submissions
    function getTestSubmissions()
        public
        view
        onlyStudent
        returns (TestSubmission[] memory)
    {
        return testSubmissions[msg.sender];
    }

    function getStudentTestSubmission(address _studentAddress)
        public
        view
        onlyGovernmentOrTeacher
        returns (TestSubmission[] memory)
    {
        return testSubmissions[_studentAddress];
    }
}
