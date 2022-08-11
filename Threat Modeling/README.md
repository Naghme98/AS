# Introduction:

In this assignment, you will perform threat modeling for an example application.


There is a company that wants to implement a youtube-like application. At this stage they are designing the system and ask you for a security consulting. They want to know what potential issues they may have and how to mitigate them.

There are different approaches to threat modeling, but in this assignment you will be applying process that mostly follows the one that described here:
https://owasp.org/www-community/Threat_Modeling_Process

Your submission have to include:
- Tables with entry points, assets, trust levels
- Data flow diagrams
- Threats summary table
- Report that contains clarifying information about your results

## Application:
You were provided with the following information about the system.

You were provided with the following information about the system.
**Features:**
- upload and delete videos
- get video streams with desired quality
- search available videos (filtering and sorting by some attributes)
- display user profile and uploaded videos
- some videos are private (only specific user) and some are hidden (not shown in search and on user page)
- display view history
- display, create and delete comments on video


**System entities:**
- user data
- user upload history
- user view history
- video data
- video objects
- comments


**System components:**
- Application servers
- Databases
- Video processing queue
- Video uploading servers
- Video object store

Little clarification about queue and object storage.


Idea of processing queue is to act as a buffer. The main server accepts uploaded video stream, split it in chunks and put it to the video queue, such that it can continue serving requests of other clients. 

Uploading servers consume raw video chunks from the queue and transforms them into suitable format for users (we have different qualities). Video decoding and encoding is computationally intensive operation. Suppose that decoding/encoding of video takes x4 of time of just uploading raw video to object store.

Thus we can have 4 uploading servers per 1 main server to make decoding/encoding take roughly the same amount of time because they can do it in parallel.


Another thing that about object storage in general

Usually, object storage is almost directly available to the user, that allows to lift undesired intensive data load on the main site and application server. Even when ACL is desired, since modern implementation provide built-in ACL capabilities.

Industry standard API for object storage is S3 (Simple Storage Service) from Amazon.

That API is adopted by other solutions, f.e. popular open source MinIO

I would recommend you to get familiar with its capabilities, when you will have free time:https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html

### 1. Decompose the application
At this step you should get an understanding of the application and how it interactswith external entities. This involves gathering information about:
- Entry points - interfaces through which potential attackers can interact with the application.
- Assets - something that the attacker is interested in, it can be some data or a state of the system (for example availability).
- Trust levels - access rights that the application will grant to external entities.
- Data flows - shows flow of control through system components for particular use cases.

**Your task is to:**

1. Describe entry points, assets and trust levels in form of tables
2. Select at least 3 use cases that you think are the most interesting and prepare Data Flow Diagrams (DFD) for them.

### 2. Determine threats
Now when you have decomposed the system you can determine possible threats.
Categorizations such as STRIDE allow to identify threats in the application in a structured and repeatable manner.
Your task is to apply STRIDE for each asset in the application and come up with a summary table with the following columns:

- Asset - for example “User credentials”.
- Category - according to STRIDE, for example “Information disclosure”. Note that you can skip category, if you think there is no threat for that data Flow that falls in that category.
- Threat - a threat itself that falls into category, for example “User credentials are exposed and obtained by an attacker”.
- Vulnerability - a particular flaw in the system that may be exploited and lead to the threat realization, for example “During the authentication process password is passed as plain text” or ”Password is stored as plain text in the database”.
- Score - there are different approaches for threat prioritization, but in this task you will try to do it based on Common Vulnerability Scoring System (CVSS). https://www.first.org/cvss/calculator/3.0
- Countermeasure - provide countermeasures that can be implemented in the system to mitigate that particular vulnerability.
