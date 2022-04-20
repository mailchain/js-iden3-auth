export const zeroKnowledgeProofType = "zeroknowledge";
export const protocolName = 'https://iden3-communication.io';
export const authorizationResponseMessageType = protocolName + "/authorization-response/v1";
export const circuits = {
    // AuthCircuitID is a type that must be used for auth circuit id definition
    AuthCircuitID: "auth",
    AuthenticationVerificationKey: `{"protocol":"groth16","curve":"bn128","nPublic":3,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["21186122754510938844473484121803028805768823868659420429167031962104213452669","11531036153408267367981904689583322772277231048216817576309813840083888223526"],["10692495955024261993776637845359675478723917354154593765559727707373795521628","4488222557627980933779869049485361123419155363899313279650131295533574955936"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["14480256767620451318587913463852985291987730174383323706971686426192206586228","13794842641958534223890803477584411495136489019918046681255402493033902669593","1"],["15899669153041742461768612098706524993401689577923839624297665212120517575519","8416106942975678531708060814592791926993765111819924718825496398881896100576","1"],["21287922739003385816480150654484934434031086395597647322040273495223392444173","7860334010448425278721389847502162976670934187890845446945915828310145702769","1"],["11065398733589914616819940103547091917179463489998190517391929200753651172846","16010781869086024312453962077351326782445934594671040759005152350849483388443","1"]]}`,
    AuthenticationPublicSignalsSchema: `{"challenge":0,"userState":1,"userID":2}`,
    // KycCircuitCircuitID is a type that must be used for kyc circuit id definition
    KycCircuitCircuitID: "kyc",
    // AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTP.circom
    AtomicQueryMTPCircuitID: "credentialAtomicQueryMTP",
    AtomicQueryMTPVerificationKey: `{"protocol":"groth16","curve":"bn128","nPublic":25,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["2516317384470477005677933398394575672754559385922262000599044671448065360143","16859622147443472181845080888624282759103852400344400046208649108117512951862"],["5554790419103019736758978401677687187888347248274265142709185612247663975517","16616548149501504746923066581983999266936143892418507535685180405929938448251"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["10209119751974272026802861695941000641181805749262912563258537296235084800697","9693538468624752478092494894393489982498011835144967632834424789938483198734","1"],["3511266824882574806332450290147886385092779581021484757010353573885976434054","18606536905470685002367197906557999286439672519722550542577741968102792880715","1"],["27341717499390527575317306248630680358261131297716153676798176844769558757","18207903514320711422679216954214479735653125553680331479668354595305182324489","1"],["5577607678939291070884062108198915621363266095458597345262191226329134903716","2453496842662487533803598591290806366818829568142649575129891147145244714571","1"],["18513589765478033590228306202179633195855431125126377696000837588536679075699","8043783355099396884030234836320495621251258307997827491468205667379601228848","1"],["798947675949019899260525549367506167298216494658797066367914560035068592155","14426274908497180912697663418731102829377865529825130524234015299993120777134","1"],["6429235961477386192381518291708673292727068348686761860205826442824033985184","16083017783244004804522843132842722708975214615203044852826077244476847782114","1"],["16591766035064756743160455828423364363183812887742653616579357777717974660895","15886486100434791428108648227017909629043031660842698127756093617254618291281","1"],["12910151212913555614553175644457253063998623131739213050611591092299132490841","846425573896321645565768359959768951010986912550793115758113686910752748716","1"],["1912932587066415983946484463677129438398979161798099986475290394456049862772","8236113219829639414355620429437203102270656211332864252865980373548506242250","1"],["7190314349386213377241874963541888573190002149562157920574648103729768274885","20255035912492100151730277472662478980963032832117784228200091899375729569461","1"],["4284232798846544967337598011893961404329309173416573572998495823935789994727","15762686004172187316484543418397072562890620529535646780181824651794601724929","1"],["3796628351075444915813482199733118234574607573281493453114559798990427655834","13149082409076033985557441730264671796614345907007394669399243352898431017217","1"],["18504377172047442067485350186672883883177644457359229406203607345241171171383","21612483792768493409465869383194381299301360567512340189089757161062649608947","1"],["11351792963490652653061645107277880526436597956809271383220021885820210009586","21159323202508975159016192650745500877564679086616593581947279603682137080908","1"],["4443908562279196975412927301934026627218123764220844892035005302618963458564","2966928321106903348452126057495706714664744840041999526475890800999691529229","1"],["12396729799303081048511069827137886571956311655907012724700947918318556079328","5126417782456421318946572501737839176313033942572590957397084248294870265765","1"],["3211071359488262143482114487245008920240380583228595393962692827759081537128","594783618905105518960013938778133572404784268438443040295674732877156215844","1"],["3003228228132092140894668350331471603633108819597082465328199649773172728417","8094902572880206506585131564807726393809245128887014006428078088026690759052","1"],["12752328100377304826839927356182835411584710437611369610768017545610739913637","4870959533025478237353485096140666091219835531128430364467696556669522451364","1"],["14743166125281678242296590332603676267914571152070998643989741645190133517161","12428469644007367665788163192314719571635335713181737179939841362666839171035","1"],["15697973560601505135237628287877858252665480822163316474457601344440862006265","21117488656936455231300527226228449420225401107007338144697618917792083935254","1"],["18079264048175722959515172577260287077482072055227404561873429504697970289869","8188656810775391648685991843417496839534269485145388478840285802350881419063","1"],["5129369021026351754804362997992516379409480079393753573170367448287316630976","10087594162701541396208174530630969603837185966332283691381781081670799410908","1"],["10620454384023403471888332548347415139310480697028067397918201008189933888419","123771019447375744038441611603067231444928915098261916310330827041380957676","1"],["15786541411191832347165520635390917405534111565831003915667764452792979750469","5861327436226369394564811190924226879843273074286812399096763717998967856077","1"]]}`,
    AtomicQueryMTPPublicSignalsSchema: `{"userID":0, "userState":1,"challenge":2,"claimSchema":3, 
"issuerClaimIdenState":4,"issuerID":5,"slotIndex":6,
"value_0": 7, "value_1": 8, "value_2": 9, "value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, 
"value_9": 15, "value_10": 16, "value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21,
"operator":22,"timestamp":23}`,
    // AtomicQuerySigCircuitID is a type for credentialAttrQuerySig.circom
    AtomicQuerySigCircuitID: "credentialAtomicQuerySig",
    AtomicQuerySigVerificationKey: `{"protocol":"groth16","curve":"bn128","nPublic":25,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["4030889886527512927464489055778264195026327234344297329342574846571936375898","14679058152716502380097457001792988184266869011990821865455662930903546850499"],["15008923684120398980662519594804495252525764101488973995091971434530983272559","18253284413000287008485064683989995992720787829777701786643516172423024866523"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["19358840197597499801228573201449916612352532020047381950057569384056591767602","18822778438282039087227631250754800611734737028272198362848147369016099576426","1"],["7604349467235969496812902114804321724079908709527091126435191176459020095036","14202083016402639456079115850797030575991875677362031932625634375758122738195","1"],["6284727474239620201158905598814505717708087424179647049535918547117243606885","7456246283321857075887721082686835929349887506557757694475846374244369570776","1"],["19661232049808231768547595122515368739753334205778196998816684092362647730235","19352215016062691090629847726765948244047816045874045574056673654531115181617","1"],["19324117217954813614637707009324012953415474208590015923498288516428101333104","9898726713196193623008699724210699580248246556499599778497872407618041888102","1"],["8492003098768606602399452070022052644568932813259193484071156802420511747152","19156039892547798332433257444310851675493901779958345335649732723536145808425","1"],["3863751351332911753697485794781960795455642725635961864680992553970267128983","4290595758030953583566154348695379802288573941790214014051456140203222720313","1"],["13538534291726578764856457449745280381867869722473101226969568164512376690778","12624166342550172446857999470683649726457216071747371188176054278953908288997","1"],["830120411425776703392225538088474683797236214464649578782426194731230616438","5719248764611631803760822047741935576343442703994617028776555555510709882467","1"],["5672571715208574589092035087096346121071911881655663969906697045716501866375","1332132985843167617915005971870058587343676597725244455012295844091311383928","1"],["1607869602938675826720738264539937308739469678636032199590453702910740973572","4088617721088681842535065752101405135079969275445763593706022660141189374247","1"],["2122164324480577677984899842541961790605436966771556505820462477458289424415","5949962449355965195385156798854871272707694295242552314330385829087554963381","1"],["18704261872688712480542538734347876873102354055861443741860823716193960410913","13376245200435168667332133389205367813862628801923622212449856190796934445761","1"],["20025823515171037871650203631854653431995828568521110523971129948215545456234","4070040873160799841429818582653597270309770995025469251394368497551071293287","1"],["21844262429035425769597626090987622291719424983338924589502341368176525562709","10785699587361703609322350524786498500219157640356753282500710050476489907756","1"],["16525211849242361108694302862077499825704280077577893900312117802295271211808","19275460264680298732300020287922678800605323797992348908937019541451077340752","1"],["2077664423820180957188707533848405322135181578027401907588806639361167714477","2505818974640155138007052491341350870055432401181029260903547217788055918575","1"],["2945333398086504563512979432196074503374734888197110272361174704461925773616","7348924755105531959493486666989416935283974264965113682182631313216940733238","1"],["591969280482561483202327762793580727874835803022899846175312940081121127849","17787300778509746536074067182559367738305191497513235002461130227179949900449","1"],["17986703855705293135590007961155042293475265279715726267696443956550095661460","6963830823666215446191186638866841037445864026249882512951549197225079568385","1"],["13836256541867762230401962256378960545574806420577750884656078399133853726956","18999562270967523879578478189663118789783015267768695596908208188771164541670","1"],["18859185232389566198700759206242631430203694357200560813309298852805888622252","1499357988538409584701964090717196447124587823213833132139706890987070602859","1"],["16721505530199685333838141098952018689602832287632543418479221206363888861492","19280020160574311158036227346075742078113440377493759148163671706691874537210","1"],["12466168921606684391997562942236086866982956536216418073904061823114760549207","15355708241605229135110172028520883755635252829982382289910002999975499725503","1"],["10163842672858939506823927936106561870158445838300552083178092884054690398017","12572102581685413920519981893499461971583631992332002976076972691630866255841","1"],["16879229262584565164920654096554499867968635862232747139965668550295261989559","12769123531704735505692279475948357023014785639913034968842550605513424028869","1"]]}`,
    AtomicQuerySigPublicSignalsSchema: `{"userID": 0, "userState": 1, "challenge": 2, 
"claimSchema": 3, "issuerID": 4,"issuerState":5, "slotIndex":6, "value_0": 7, "value_1": 8, "value_2": 9, 
"value_3": 10, "value_4": 11, "value_5": 12, "value_6": 13, "value_7": 14, "value_9": 15, "value_10": 16, 
"value_11": 17, "value_12": 18, "value_13": 19, "value_14": 20, "value_15": 21, "operator": 22, "timestamp": 23}`,
    // AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTPWithRelay.circom
    AtomicQueryMTPWithRelayCircuitID: "credentialAtomicQueryMTPWithRelay",
    // AtomicQuerySigCircuitID is a type for credentialAttrQuerySigWithRelay.circom
    AtomicQuerySigWithRelayCircuitID: "credentialAtomicQuerySigWithRelay"
};

export const identifierAttribute = "user_identifier";
export const challengeAttribute = "challenge";
export const stateAttribute = "user_state";
