import copy
try:
	from items import items
except:
	from design.items import items

drops={
	"gold":{
		"base":0.64,#originally 0.75
		"random":0.8,#originally 1
		"x10":(1.0/32),#originally 1/12 - later 1/15 - later 1/20 - now 1/32 [03/02/17]
		"x50":(1.0/480),#originally 1/200 - later 1/300 - later 1/400 - now 1/480 [03/02/17]
	},
	"maps":{
		"global_static":[
		
		],
		"global":[
			#[0.00001,"ornament"],
			#[0.00003,"mistletoe"],
			#[0.00001,"candycane"],
			#[0.000001,"open","xN"],
			#[0.00006,"ornament"],
			#[0.00018,"mistletoe"],
			#[0.00005,"candycane"],
			#[0.00001,"open","xN"],
			#[0.00005,"candy0"], #originally 4X [11/10/19]
			#[0.00125,"candy1"], #originally 4X [11/10/19]
			#[0.000015,"goldenegg"], #originally 0.000005
			#[0.000001,"5bucks"],
			#[0.0002,"gift0"],
			#[0.004,"gift1"],
			#[0.0006,"ornament"],
			#[0.0018,"mistletoe"],
			#[0.0005,"candycane"],
			#[0.0001,"open","xN"],
			#[0.0004,"redenvelope"],
			#[0.00005,"goldenegg"],
			#[0.009,"open","eastereggs"], #originally 0.009
			#[0.0001,"redenvelopev2"],
			#[0.0001,"redenvelopev3"],
			[0.00005,"greenenvelope"],
			#[0.0001,"redenvelopev4"],
			#[0.001,"candypop"],
		],
		"main":[
			[0.0007,"ringsj"],
			[0.0006,"hpamulet"],
			[0.0006,"hpbelt"],
			[0.00007,"gem0"],
			[0.0001,"wcap"],
			[0.0001,"wshoes"],
			#[0.00005,"goldenegg"],
			#[0.009,"open","eastereggs"],
			#[0.0012,"ornament"],
			#[0.001,"mistletoe"],
			#[0.001,"candycane"],
		],
		"winter_cave":[
			[0.0005,"open","statring"],
			[0.000001,"angelwings"],
			#[0.002,"ornament"],
			#[0.001,"mistletoe"],
			#[0.001,"candycane"],
		],
		"winterland":[
			[0.0001,"wattire"],
			[0.0005,"open","statring"], #previously 0.0003
			#[0.00005,"goldenegg"],
			#[0.009,"open","eastereggs"],
			#[0.002,"ornament"],
			#[0.001,"mistletoe"],
			#[0.001,"candycane"],
		],
		"halloween":[
			[0.0001,"wgloves"],
			[0.0001,"wbreeches"],
			[0.0007,"open","statamulet"],
			#[0.00005,"goldenegg"],
			#[0.009,"open","eastereggs"],
			#[0.0004,"intamulet"],
			#[0.0004,"stramulet"],
			#[0.0001,"candy0"], #originally 0.0002
			#[0.002,"candy1"], #originally 0.004
			#[0.001,"ornament"],
			#[0.001,"mistletoe"],
			#[0.001,"candycane"],
			#[0.0001,"candy0v2"], #originally 0.0002
			#[0.002,"candy1v2"], #originally 0.004
		],
		"spookytown":[
			[0.0001,"wbreeches"],
			#[0.0002,"candy0v2"], #originally 0.0002
			#[0.003,"candy1v2"],
			[0.0007,"open","statbelt"],
		],
		"cave":[
			[0.0001,"wattire"],
			[0.0001,"wgloves"],
			[0.0004,"ringsj"],
			[0.0006,"hpamulet"],
			[0.0006,"hpbelt"],
			[0.00008,"gem0"],
			[1.0/600000,"cryptkey"]
			#[0.001,"ornament"],
			#[0.001,"mistletoe"],
			#[0.001,"candycane"],
		],
		"maintest":[
			[0.001,"ringsj"],
			[0.0007,"hpamulet"],
			[0.0007,"hpbelt"],
		],
		"arena":[
			[0.00008,"gem0"],
		],
		"mansion":[
			[0.0001,"wbreeches"],
			[12.0/100000,"lostearring"],
		],
	},
	"monsters":{
		"hen":[
			[1.0,"whiteegg"],
			[0.1,"whiteegg"],
		],
		"rooster":[
			[1.0/10000,"brownegg"],
		],
		"goo":[
			#[0.1/10,"shells",50],
			[0.1/800000,"shells",50],
			[1.0/5000,"slimestaff"],
			[1.0/1000,"gslime"], #1 .0/1000
			#[100,"emotionjar",1,"hearts_single"],
			#[1.0,"emotionjar",1,"drop_egg"],
			#[1.0/10,"cxjar",1,"wings102"],
			#[1.0,"cxjar",1,"hat100"],
		], #,[0.5,"open","lightmage"]
		"crab":[
			[2.0/10000000,"suckerpunch"],
			[5.0/1000,"seashell"],
			[1.0/1000,"crabclaw"],
			[1.0/20000,"cclaw"],
		],
		"bee":[
			[1.0/100,"beewings"],
			[1.0/6000,"stinger"],
		],
		"porcupine":[
			[1.0/1000,"pleather"],
			[1.0/5000,"hbow"],
		],
		"stoneworm":[
			[1.0/12000,"swifty"],
			[1.0/300,"dstones"],
		],
		"minimush":[
			[1.0/60,"spores"],
			[1.0/5000,"mushroomstaff"],
			[1.0/9000000,"cxjar",1,"hat407"],
			[1.0/60000000,"cxjar",1,"hat406"],
		],
		"frog":[
			[16.0/100,"seashell"],
			[1/100000.0,"5bucks"],
			[1/400.0,"lotusf"]
		],
		"squigtoad":[
			[5.0/100,"seashell"],
			[1.0/400,"frogt"],
		],
		"osnake":[
			[1.0/10000,"snakeoil"],
			[1.0/2000,"snakefang"],
		],
		"snake":[
			[1.0/100000,"snakeoil"],
		],
		"rat":[
			[1.0/500,"rattail"],
		],
		"armadillo":[
			[1.0/20000,"sshield"],
			[8.0/10000,"ascale"],
		],
		"squig":[
			[12.0/1000,"seashell"],
			[1.0/20000,"ink"],
		],
		"cgoo":[
			[8.0/1000,"gem1"],
			[0.00008,"shadowstone"],
			[1.0/20000,"ijx"],
		],
		"poisio":[
			[3.2/1000,"poison"],
			[1.0/3000,"smush"]
		],
		"snowman":[
			[0.01,"iceskates"],
			[0.05,"xmace"],
			[0.3,"candycane"],
			[0.2,"candycane"],
			[0.1,"candycane"],
			[0.1,"candycane"],
			[0.1,"candycane"],
			[0.1,"mistletoe"],
			[0.00075,"offering"],
			[1,"carrot"],
			[1,"snowball"],
			[1,"snowball"],
			[0.0025,"wbookhs"],
		],
		"tiger":[#every hit
			[0.1,"tigerhelmet"],
			[0.001,"tigercape"],
			[0.001,"tigerstone"],
			[0.01,"tigershield"],
		],
		"arcticbee":[
			[0.00005,"essenceoffrost"],
			[1.0/1000,"bfur"],
		],
		"mole":[
			[0.012,"gemfragment"],
			[2.0/100000,"molesteeth"]
		],
		"oneeye":[
			[1.0/500000,"amuletofm"],
			[1.0/3000000,"mpxbelt"]
		],
		"crabx":[
			[4.0/10000000,"suckerpunch"],
			[2.0/100,"seashell"],
			[1.0/500,"cclaw"],
			[1.0/10000,"cshell"],
		],
		"crabxx":[
			[4.0/10000,"suckerpunch"],
			[100,"seashell"],
			[100,"seashell"],
			[500,"cclaw"],
			[10000,"cshell"],
			[1000,"funtoken"],
			[1000,"funtoken"],
			[1000,"funtoken"],
			[10,"funtoken"],
			[10,"funtoken"],
		],
		"rgoo":[
			[20,"funtoken"],
			[0.025,"open","lglitch"]
		],
		"bgoo":[
			[0.25,"funtoken"],
		],
		"croc":[
			[9.0/10000,"cscale"],
		],
		"prat":[
			[10.0*8/10000000,"platinumnugget"],
			[5.0/1000,"rfangs"],
		],
		"boar":[[0.01,"leather"],[1.0/200000,"btusk"]],
		"tortoise":[[2.0/10000,"shield"],[1.0/1000,"seashell"]],
		"wolf":[[1.0/40,"leather"]],
		"wolfie":[[1.0/50,"leather"]],
		"stompy":[[1,"leather"],[1,"leather"],[1,"leather"],[1,"leather"],[1.0/500,"snring"]], #[0.3,"mistletoe"],[0.4,"candycane"],[1,"ornament"],[1,"ornament"],
		"dknight2":[
			[0.01,"shield"], #0.025 before [03/12/16]
			[0.0008,"fireblade"], #0.0016 before
		],
		"mvampire":[[0.10,"intearring"],[0.10,"strearring"],[0.10,"dexearring"],[0.05,"firestaff"],[0.03,"mcape"],[0.01,"forscroll"],[1.0/400000,"cxjar",1,"coolblueg"],[1.0/80000,"sanguine"]],
		"fvampire":[[0.30,"open","statamulet"],[0.04,"firestaff"],[0.01,"mcape"],[0.01,"armorbox"],[0.01,"forscroll"],[1.0/200000,"cxjar",1,"catbatg"],[1.0/40,"offeringp"],[1.0/50000,"sanguine"]],
		#"phoenix":[[0.08,"intearring"],[0.08,"strearring"],[0.08,"dexearring"],[0.02,"firestaff"],[0.02,"fireblade"]],
		"phoenix":[[0.7,"vitscroll"],[0.12,"intearring"],[0.12,"strearring"],[0.12,"dexearring"],[0.12,"vitearring"],[0.04,"firestaff"],[0.04,"fireblade"],[1.0/120000,"fcape"],[1.0/600,"offeringp"],[1.0/64000000,"cxjar",1,"hairdo606"]],
		"mechagnome":[[0.2,"electronics"],[0.2,"electronics"],[0.2,"electronics"],[0.00001,"networkcard"],[1.0/10000000,"mpxamulet"]],
		"bat":[[4.0/1000,"wbook0"],[5.0/1000,"bwing"],[1.0/100000000,"cxjar",1,"wings102"]],
		"scorpion":[
			[6.0/10000,"quiver"],
			[1.0/4000,"sstinger"],
		],
		"pinkgoblin":[
			[1.0/24000,"bkey"],
		],
		"spider":[[0.001,"spidersilk"],[1.0/500000,"offeringp"]],
		"tinyp":[[1.0/1,"offeringp"]],
		"gscorpion":[[0.002,"quiver"]],
		"xscorpion":[[0.0024,"quiver"],[0.00024,"vitscroll"],[2.0/1000000,"glitch"],[8.0/100000,"svenom"]],
		"bscorpion":[[1.0/20,"offeringp"]],
		#"ghost":[[0.001,"candy0"]],
		"ghost":[[0.0002,"pmace"]], #0.001 was tooooo high
		"booboo":[[0.005,"essenceofether"],[5.0/100000,"ectoplasm"]],
		"mummy":[
			[1.0/4000,"open","weaponofthedead"],
			[1.0/500,"bandages"],
		],
		"iceroamer":[
			[0.0001,"essenceoffrost"],
			[0.00001,"frozenkey"],
		],
		"icegolem":[
			[5,"frozenkey"],
			[10,"essenceoffrost"],
		],
		"fireroamer":[
			[1.0/1442,"orbofstr"],
			[1.0/1442,"orbofdex"],
			[1.0/64,"essenceoffire"],
		],
		"pppompom":[
			[1.0/1000,"orbofint"],
			[1.0/1000,"orbofvit"],
		],
		"mrpumpkin":[[100,"candy0"],[100,"candy1"],[100,"candy1"],[10,"phelmet"],[10.0/100000,"cxjar",1,"gcandle"],[10.0/100000,"cxjar",1,"breyes"],],
		"mrgreen":[[100,"candy0"],[100,"candy1"],[100,"candy1"],[10,"gphelmet"],[15.0/100000,"cxjar",1,"bathat"],[1.0/100,"hdagger"]],
		"jr":[
			#[1,"swirlipop"],
			[0.1,"candy0"],[0.1,"candy1"], #[1,"candy1v2"],[1,"candy1v2"],[1,"candy1v2"],[1,"candy1v2"],
			[1,"pstem"],
			[1.0/1000,"hdagger"],
			[1,"ololipop"],
		],
		"greenjr":[
			#[1,"greenbomb"],
			[0.1,"candy0"],[0.1,"candy1"], #[1,"candy1v2"],[1,"candy1v2"],[1,"candy1v2"],[1,"candy1v2"],
			[1.0/1000,"bcandle"],
			[1.0/1000,"hdagger"],
			[1,"glolipop"],
		],
		"slenderman":[
			[1.0/200,"cxjar",1,"mmakeup13"],
			[1.0/20,"sbelt"],
			[100,"candy0"],
			[100,"candy1"],
		],
		"bbpompom":[
			[0.0004,"essenceoffrost"],
			[6.0/1000,"lspores"],
			[1.0/1000000,"cxjar",1,"hat407"],
			[1.0/20000000,"cxjar",1,"hat406"],
		],
		"skeletor":[[0.5,"gem1"],[0.10,"gem1"],[0.10,"gem1"],[0.10,"gem1"],[0.02,"weaponbox"],[0.05,"armorbox"],[0.01,"shadowstone"],[1.0/5000,"scythe"]],
		"greenfairy":[[1,"stick"]],
		"redfairy":[[1,"stick"]],
		"bluefairy":[[1,"stick"]],
		"rudolph":[[1,"coal"],[1,"rednose"],[1,"iceskates"]],
		"pinkgoo":[
			[0.3,"cupid"],
			[0.001,"emptyheart"],
			[0.0005,"solitaire"],
		],
		"target_ar500red":[
			[1,"shadowstone"],
			[0.5,"shadowstone"],
			[0.25,"shadowstone"],
			[0.125,"shadowstone"],
			[0.0625,"shadowstone"],
		],
		"franky":[
			[30,"cryptkey"],
			[20,"candy0"],
			[20,"candy0"],
			[20,"candy0"],
			[20,"candy0"],
			[200,"candy1"],
			[200,"candy1"],
			[200,"candy1"],
			[200,"candy1"],
			[10,"frankypants"],
			[1.0/2000,"mpxgloves"],
			[1.0/5000,"ukey"],
			[1.0/8000,"cxjar",1,"marmor3h"],
		],
		"dragold":[
			[3,"goldenegg"],
			[3,"goldenegg"],
			[3,"goldenegg"],
			[50,"essenceoffire"],
			[40,"essenceoffire"],
			[30,"essenceoffire"],
			[20,"essenceoffire"],
			[10,"essenceoffire"],
			[10,"essenceoffire"],
			[0.2,"offering"],
			[0.5,"lmace"],
			[2.0/4/1000/1000,"cxjar",1,"hat400"],
			[2.0/6/1000/1000,"chrysalis0"],
		],
		"ent":[
			[1,"essenceofnature"],
			[0.02,"woodensword"],
			[1/100000.0,"stick"],
			[1/200000.0,"nheart"],
		],
		"plantoid":[
			[0.004,"essenceofnature"],
			[7.0/10000000,"ringofluck"],
		],
		"grinch":[
			[0.6/100,"ringhs"],
			[10,"wbookhs"],
			[20.0,"gcape"],
			[1.0/10000,"northstar"],
			[1.0/10000,"dkey"],
			[10,"iceskates"],
			[1,"sweaterhs"],
		],
		"bigbird":[
			[0.05,"feather0"],
		],
		"harpy":[
			[0.01,"feather1"],
			[0.01,"feather1"],
			[0.01,"feather1"],
			[0.01,"feather1"],
			[0.01/600.0,"harpybow"],
			[0.1,"essenceoffrost"],
			[1.0/2000,"harbringer"],
		],
		"rharpy":[
			[0.05,"feather1"],
			[0.05,"feather1"],
			[0.05,"feather1"],
			[0.05,"feather1"],
			[0.05/100.0,"harpybow"],
			[1,"essenceoffrost"],
			[1,"essenceoffrost"],
		],
		"wabbit":[
			[10,"open","eastereggs"],
			[10,"open","eastereggs"],
			[10,"open","eastereggs"],
			[10,"open","eastereggs"],
			[10,"open","eastereggs"],
			[10,"open","eastereggs"],

			[1,"open","eastereggs"],
			[0.9,"open","eastereggs"],
			[0.8,"open","eastereggs"],
			[0.2,"open","eastereggs"],
			[0.2,"open","eastereggs"],
			[0.2,"open","eastereggs"],
			[0.01,"goldenegg"], #originally 0.02 [11/04/19]
			[0.01,"open","basketofeggs"],
			[0.001,"emotionjar",1,"drop_egg"],
		],
		"goldenbat":[
			[0.8,"handofmidas"],
			[1,"bataxe"],
			[0.01,"bfang"],
		],
		"a1":[
			[1.0/20000,"vring"],
			[1.0/2000,"vorb"],
			[1.0/1000,"vcape"],
			[1.0/10,"vattire"],
			[0.001,"vblood"],
		],
		"a2":[
			[1.0/20000,"vring"],
			[1.0/2000,"cxjar",1,"hairdo607"],
			[1.0/200,"vdagger"],
			[1.0/200,"vdagger"],
			[0.001,"vblood"],
		],
		"a3":[
			[1.0/10,"vgloves"],
			[1.0/200,"vhammer"],
			[1.0/200,"vhammer"],
			[0.001,"vblood"],
		],
		"a4":[
			[1.0/1000,"vorb"],
			[1.0/200,"cyber"],
			[1.0/20000,"cxjar",1,"mask104"],
			[0.001,"vblood"],
		],
		"a5":[
			[1.0/10,"vboots"],
			[1.0/2000,"cxjar",1,"hairdo608"],
			[0.001,"vblood"],
			[1.0/10000,"sbelt"],
		],
		"a6":[
			[1.0/10,"mbelt"],
			[1.0/200,"cyber"],
			[1.0/20000,"cxjar",1,"mask105"],
			[0.001,"vblood"],
		],
		"a7":[
			[1.0,"fieldgen0"],
			[1.0,"oozingterror"],
			[0.001,"vblood"],
		],
		"a8":[
			[1.0/10,"vgloves"],
			[1.0/100,"vstaff"],
			[0.001,"vblood"],
			[1.0/4000,"sbelt"],
		],
		"vbat":[
			[1.0/2,"cearring"],
			[1.0/2,"cring"],
		],
		"xmagex":[
			[1.0/50,"zapper"],
			[1.0/5000,"trigger"],
			[1.0/500,"mpxamulet"],
			[1.0/500,"mpxgloves"],
			[1.0/200000,"warpvest"],
			[1.0/500,"starkillers"],
			[1.0/100,"sbelt"],
		],
	},
	"konami":[
		[6.0/10000000,"powerglove"],
		[2.0/1000000000,"goldenpowerglove"],
	],
	"statamulet":[
		[1,"intamulet"],
		[1.2,"stramulet"],
		[1,"dexamulet"],
	],
	"statbelt":[
		[1,"intbelt"],
		[1.05,"strbelt"],
		[1,"dexbelt"],
	],
	"statring":[
		[1,"intring"],
		[1,"vitring"],
		[1,"dexring"],
		[1.2,"strring"],
	],
	"basicelixir":[
		[1,"elixirvit0"],
		[0.1,"elixirvit1"],
		[0.01,"elixirvit2"],
		[1,"elixirstr0"],
		[0.1,"elixirstr1"],
		[0.01,"elixirstr2"],
		[1,"elixirdex0"],
		[0.1,"elixirdex1"],
		[0.01,"elixirdex2"],
		[1,"elixirint0"],
		[0.1,"elixirint1"],
		[0.01,"elixirint2"],
	],
	#quests
	"glitch":[], #populated below
	"lglitch":[],
	"gemfragment":[
		[0.5,"gem0"],
		[0.00001,"fury"],
		[1,"t2stramulet"],
		[1,"t2intamulet"],
		[1,"t2dexamulet"],
	],
	"seashell":[
		[0.000001,"vitscroll",10],
		[1,"open","basicelixir"],
		[0.00002,"fury"],
	],
	"leather":[
		[20,"cape"],
		[1,"bcape"],
		[0.5,"open","armorbox"],
	],
	"lostearring0":[ #0
		[1,"open","armorbox"],
	],
	"lostearring1":[ #300k - 3X
		[1,"open","weaponbox"],
	],
	"lostearring2":[ #9.2m - 9X
		[1,"wbook1"],
		[0.25,"t2quiver"],
	],
	"lostearring3":[ #36m - 27X
		[0.5,"fury"],
		[5,"handofmidas"],
	],
	"lostearring4":[ #~120m - 81X
		[1,"hhelmet"], #tier3
		[0.8,"harmor"],
		[1,"hpants"],
		[1.1,"hgloves"],
		[0.5,"hboots"],
		[0.1,"xhelmet"], #tier4
		[0.08,"xarmor"],
		[0.1,"xpants"],
		[0.11,"xgloves"],
		[0.05,"xboots"],
	],
	#events
	"mistletoe":[
		[0.12,"eggnog"],
		[1,"hotchocolate"],
		[1,"warmscarf"],
		[1,"snowball",10],
		[0.1,"santasbelt"],
		[1,"candycanesword"],
		[1,"ornamentstaff"],
		[0.8,"merry"],
		[0.05,"mshield"],
		[1,"rednose"],
		[1,"xmashat"],
		[1,"xmasshoes"],
		[0.8,"xmassweater"],
		[1,"xmaspants"],
		[0.8,"mittens"],
		[0.02,"angelwings"],
		#[0.1,"orbofsc"],
		[0.008,"supermittens"],
		[0.0001,"mearring"],
		[3.6,"open","gem0"],
	],
	"candycane":[
		[0.05,"open","xN"],
		[0.1,"eggnog"],
		[1,"hotchocolate"],
		[1,"warmscarf"],
		[1,"snowball",10],
		[0.1,"snowflakes"],
		[0.1,"santasbelt"],
		[1,"candycanesword"],
		[1,"ornamentstaff"],
		[0.8,"merry"],
		[0.05,"mshield"],
		[1,"rednose"],
		[1,"xmashat"],
		[1,"xmasshoes"],
		[1,"xmassweater"],
		[1,"xmaspants"],
		[1,"mittens"],
		[0.02,"angelwings"],
		#[0.1,"orbofsc"],
		[0.008,"supermittens"],
		[3.6,"open","gem0"],
		[0.00001,"northstar"],
		[0.01,"shells",200],
	],
	"5bucks":[
		[0.02,"5bucks",2],
		[1,"shells",800],
	],
	"ornament":[
		[0.1,"eggnog"],
		[1,"hotchocolate"],
		[1,"warmscarf"],
		[1,"snowball",10],
		[0.1,"santasbelt"],
		[1,"candycanesword"],
		[1,"ornamentstaff"],
		[0.05,"mshield"],
		[0.8,"merry"],
		[1,"rednose"],
		[1,"xmashat"],
		[1,"xmasshoes"],
		[0.8,"xmassweater"],
		[1,"xmaspants"],
		[0.8,"mittens"],
		[0.02,"angelwings"],
		#[0.1,"orbofsc"],
		[0.012,"supermittens"],
		[3.6,"open","gem0"],
	],
	"xbox":[
		[1,"open","armorx"],
		[1,"harbringer"],
		[1,"t2quiver"],
		[0.1,"exoarm"],
		[0.06,"fury"],
		[0.12,"starkillers"],
		[0.01,"northstar"],
	],
	"redenvelope":[
		[1000,"gold",500000],
		[1,"gold",100000000],
		[10,"cdragon"],
		[40,"puppyer"],
	],
	"redenvelopev2_shouldhavebeen":[
		[2000,"gold",50000],
		[1,"gold",10000000],
		[300,"firecrackers"],
		[0.1,"dragondagger"],
		[1,"cdragon"],
	],
	"redenvelopev2":[
		[2000,"gold",500000],
		[2,"gold",10000000],
		[3000,"firecrackers"],
		[1,"dragondagger"],
		[1,"cdragon"],
	],
	"redenvelopev3":[
		[2000,"gold",50000],
		[1,"gold",10000000],
		[300,"firecrackers"],
		[0.1,"dragondagger"],
		[1,"cdragon"],
	],
	"redenvelopev4":[
		[2000,"gold",50000],
		[1,"gold",10000000],
		[300,"firecrackers"],
		[0.1,"dragondagger"],
		[1,"cdragon"],
	],
	"greenenvelope":[
		[2000,"gold",50000],
		[1,"gold",10000000],
		[300,"firecrackers"],
		[0.1,"dragondagger",None,None,"lucky"],
		[0.3,"lmace",None,None,"lucky"],
		[1,"oxhelmet",None,None,"lucky"],
		[0.1,"cdragon",None,None,"lucky"],
	],
	"eastereggs":[
		[1,"egg0"],
		[1,"egg1"],
		[1,"egg2"],
		[1,"egg3"],
		[1,"egg4"],
		[1,"egg5"],
		[1,"egg6"],
		[1,"egg7"],
		[1,"egg8"],
	],
	"xN":[
		[1,"x0"],
		[1,"x1"],
		[1,"x2"],
		[1,"x3"],
		[1,"x4"],
		[1,"x5"],
		[1,"x6"],
		[1,"x7"],
		[1,"x8"],
	],
	"goldenegg":[
		[100,"gold",1000000],
		[10,"gold",10000000],
		[1,"gold",100000000],
	],
	"basketofeggs":[
		[1,"bunnyelixir"],
		#[1,"bunnyears"],
		#[1,"pyjamas"],
		[1,"eears"],
		[1,"epyjamas"],
		[1,"ecape"],
		[1,"eslippers"],
		[0.5,"carrotsword"],
		[0.1,"bataxe"],
		[0.04,"pinkie"],
		[0.04,"oozingterror"],
		[0.04,"harbringer"],
		[0.001,"rabbitsfoot"], #originally 0.02
	],
	"gift0":[
		#[1,"tristone"],
		[1,"ftrinket"],
		[1,"poker"],
		[0.5,"partyhat"],
		[0.008,"mysterybox"],
		[0.1,"cake"],
		[0.5,"open","armorx"],
		[0.18,"scroll3"],
	],
	"gift1":[
		[1,"open","thrash"],
		[0.4,"cake"],
		[0.2,"poker"],
		[1,"confetti"],
		#[1,"tristone"],
		[0.8,"partyhat"],
		[0.1,"gift0"],
		[0.1,"open","armorbox"],
		[0.05,"ftrinket"],
		[0.006,"scroll3"],
		[0.006,"mysterybox"],
		[0.002,"offering"],
		[0.0003,"luckbooster"],
	],
	#thrash
	"thrash":[
		[1,"coat"],
		[1,"shoes"],
		[1,"pants"],
		[1,"gloves"],
		[1,"helmet"],
		[1,"empty"],
	],
	#gems
	"gem0":[
		[0.5,"weaponbox"],
		[1.5,"armorbox"],
		[0.5,"gold",100000],
		[1,"gold",200000],
		[1,"gold",200000],
		[1,"gold",400000],
		[0.5,"gold",800000],
		[0.10,"gold",1600000],
		[0.10,"gold",3200000],
		[0.05,"gold",6400000],
		[0.05,"offering"],
		[1,"scroll1",10],
		[0.5,"cscroll1",4],
		[0.001,"shells",200],
		[0.0001,"scroll3",1],
		[0.0001,"cscroll3",1],
	],
	"gem1_old":[
		[0.1,"weaponbox"],
		[0.3,"armorbox"],
		[0.1,"gem0"],
		[3,"gold",50000],
		[2,"gold",100000],
		[0.5,"gold",200000],
		[0.1,"gold",400000],
		[0.01,"gold",800000],
		[0.001,"gold",1600000],
		[0.001,"gold",3200000],
		[0.001,"offering"],
		[0.5,"scroll0",75],
		[0.5,"cscroll0",8],
		[0.2,"scroll1",2],
		[0.2,"cscroll1",1],
		[0.001,"shells",50],
	],
	"gem1":[
		[0.1,"weaponbox"],
		[0.3,"armorbox"],
		[0.001,"offering"],
		[0.001,"shells",50],
		[1,"open","thrash"],
		[0.012,"gemfragment"],
	],
	"candypop":[
		[1,"weaponbox"],
		[1,"armorbox"],
		[10,"gold",10000],
		[10,"hpot1",100],
		[10,"mpot1",100],
		[10,"scroll0",5],
		[5,"cscroll0",2],
		[1,"scroll1",1],
		[0.5,"cscroll1",1],
		[0.0001,"shells",50],
		[0.1,"emptyheart"],
		[1,"cupid"],
	],
	"candy0":[
		[1,"pmaceofthedead"],
		[0.008,"spookyamulet"],
		[1,"gold",480000],
		[0.0005,"cxjar",1,"hat410"],
		[0.001,"vblood"],
		[0.12,"lantern"],
		[0.1,"talkingskull"],
		[1,"jacko"],
		[0.1,"gphelmet"],
		[1,"throwingstars"],
		[2,"pumpkinspice"],
		[0.1,"candy0",5],
		[1,"open","weaponofthedead"],
		[0.008,"mysterybox"],
		[0.001,"gbow"],
		[0.0005,"starkillers"],
		[0.002,"swirlipop"],
		[0.002,"greenbomb"],
		[0.0005,"fury"],
		[0.1,"open","armorx"],
	],
	"candy1":[
		[0.8,"skullamulet"],
		[0.05,"broom"],
		[1,"gold",80000],
		[0.03,"lantern"],
		[0.8,"phelmet"],
		[4.5,"smoke"],
		[4.5,"pumpkinspice"],
		[0.4,"candy0"],
		[0.002,"swirlipop"],
		[0.002,"greenbomb"],
		[0.0001,"starkillers"],
		[0.0001,"fury"],
		[0.0012,"handofmidas"],
		[0.007,"harbringer"],
		[0.008,"oozingterror"],
		[0.001,"open","armorx"],
		[0.0001,"cxjar",1,"hairdo609"],
	],
	"candy0v2":[
		[0.12,"lantern"],
		[1,"gphelmet"],
		[1,"throwingstars"],
		[2,"pumpkinspice"],
		[0.1,"candy0v2",5],
		[1,"open","weaponofthedead"],
		[0.008,"mysterybox"],
		[0.002,"starkillers"],
		[0.002,"swirlipop"],
		[0.002,"greenbomb"],
		[0.001,"fury"],
		[0.1,"open","armorx"],
	],
	"candy1v2":[
		[0.03,"lantern"],
		[0.8,"phelmet"],
		[4.5,"smoke"],
		[4.5,"pumpkinspice"],
		[0.4,"candy0v2"],
		[0.002,"swirlipop"],
		[0.002,"greenbomb"],
		[0.0012,"starkillers"],
		[0.0012,"fury"],
		[0.0012,"handofmidas"],
		[0.004,"harbringer"],
		[0.001,"open","armorx"],
	],
	"candy0v3":[
		[1,"gold",480000],
		[0.001,"vblood"],
		[0.12,"lantern"],
		[0.1,"talkingskull"],
		[1,"jacko"],
		[0.1,"gphelmet"],
		[1,"throwingstars"],
		[2,"pumpkinspice"],
		[0.1,"candy0v3",5],
		[1,"open","weaponofthedead"],
		[0.008,"mysterybox"],
		[0.002,"starkillers"],
		[0.002,"swirlipop"],
		[0.002,"greenbomb"],
		[0.001,"fury"],
		[0.1,"open","armorx"],
	],
	"candy1v3":[
		[1,"gold",80000],
		[0.03,"lantern"],
		[0.8,"phelmet"],
		[4.5,"smoke"],
		[4.5,"pumpkinspice"],
		[0.4,"candy0v3"],
		[0.002,"swirlipop"],
		[0.002,"greenbomb"],
		[0.0012,"starkillers"],
		[0.0012,"fury"],
		[0.0012,"handofmidas"],
		[0.004,"harbringer"],
		[0.001,"open","armorx"],
	],
	"abtesting":[
		[1,"pvptoken"],
		[1,"pvptoken",2],
		[1,"pvptoken",3],
		[0.5,"pvptoken",4],
		[0.25,"pvptoken",5],
		[0.125,"pvptoken",6],
		[0.0675,"pvptoken",20],
		[0.0025,"fury"],
	],
	"abtesting_loser":[
		[1,"pvptoken"],
		[0.5,"empty"],
	],
	"weaponofthedead":[
		[0.85,"bowofthedead"],
		[0.35,"swordofthedead"],
		[1,"maceofthedead"],
		[0.1,"pmaceofthedead"],
		[1,"staffofthedead"],
		[1,"daggerofthedead"],
	],
	"bugbountybox":[
		[1,"glitch"],
	],
	"apologybox":[
		[1,"glitch"],
	],
	"f1":[
		[14,"coat1"],
		[22,"helmet1"],
		[20,"pants1"],
		[22,"gloves1"],
		[14,"shoes1"],
		[0.5,"open","lglitch"],
	],
	"m1":[
		[200,"gemfragment"],
		[1,"bronzenugget"],
		[0.5,"goldnugget"],
		[0.1,"platinumnugget"],
		#[0.5,"open","glitch"],
		[0.1,"emotionjar",1,"hearts_single"],
	],
	"m2":[
		[100,"empty"],
		[10,"wbook0"],
		[0.1,"wbook1"],
	],
	"armorbox":[
		[14,"coat1"],
		[22,"helmet1"],
		[20,"pants1"],

		[1,"hhelmet"], #tier3
		[0.8,"harmor"],
		[1,"hpants"],
		[1.1,"hgloves"],
		[0.5,"hboots"],

		[22,"gloves1"],

		[0.1,"xhelmet"], #tier4
		[0.08,"xarmor"],
		[0.1,"xpants"],
		[0.11,"xgloves"],
		[0.05,"xboots"],

		[0.005,"fury"],
		[0.005,"starkillers"],

		[14,"shoes1"],
	],
	"armorx":[
		[1,"hhelmet"], #tier3
		[0.8,"harmor"],
		[1,"hpants"],
		[1.1,"hgloves"],
		[0.5,"hboots"],
		[0.1,"xhelmet"], #tier4
		[0.08,"xarmor"],
		[0.1,"xpants"],
		[0.11,"xgloves"],
		[0.05,"xboots"],
	],
	"mysterybox":[
		[70,"open","armorx"],
		[20,"scroll3"],
		[4,"cscroll3"],
		[1,"warpvest"],
		[1,"scroll4"],
	],
	"test":[
		[1,"armorbox"],
		[1,"open","lightmage"]
	],
	"lightmage":[
		[1,"hpot0"],
		[1,"mpot0"],
	],
	"weaponbox":[
		[1,"throwingstars"],
		[0.05,"harbringer"],
		[0.04,"oozingterror"],
		[1.4,"t2bow"],
		[1,"basher"],
		[1,"spear"],
		[1,"dagger"],
		[0.5,"pmace"],
		[1,"fireblade"],
		[0.8,"firestaff"],
		[0.04,"t3bow"],
		[0.02,"hammer"],
		[0.1,"rapier"],
		[1,"sword"],
		[0.2,"crossbow"],
	],
	"jewellerybox":[
		[1,"hpamulet"],
		[1,"hpbelt"],
	],
	"quiver":[
		[1,"leather"],
		[0.5,"leather"],
	],
	"troll":[
		[100,"tshirt0"],
		[100,"tshirt1"],
		[100,"tshirt2"],
		[20,"tshirt3"],
		[10,"tshirt4"],
		[0.1,"tshirt88"],
		[1,"tshirt6"],
		[1,"tshirt7"],
		[0.8,"tshirt8"],
		[0.8,"tshirt9"],
		[0.0001,"luckyt"],
	],
	"skins":{
		#gold 0.05 - perfect ones
		"gold":[
		],
		#silver 0.1 - good ones
		"silver":[
			"mwarrior_cool","mnwarrior",
		],
		#bronze 0.80 - nice/usable ones
		"bronze":[

		],
		#normal 0.05 - mostly NPC's
		"normal":[
		],
	},
	"cosmo0":[
		#[1.0,"cxbundle","rogueb"],
		#[1,"cx","lchar1b"],
		[1.0/2,"cx","marmor10a"],
		[1.0,"cx","marmor10b"],
		[1.0/1.2,"cx","marmor10c"],
		[1.0,"cx","marmor10g"],
		[1.0,"cx","marmor10h"],
		[1.0,"cx","marmor11a"],
		[1.0/2,"cx","marmor11b"],
		[1.0,"cx","marmor11c"],
		[1.0/2,"cx","marmor11d"],
		[1.0/2,"cx","marmor11e"],
		[1.0,"cx","marmor11f"],
		[1.0,"cx","marmor11g"],
		[1.0,"cx","marmor11h"],
		[1.0/2,"cx","marmor1b"],
		[1.0/2,"cx","marmor1c"],
		[1.0,"cx","marmor2a"],
		[1.0,"cx","marmor2b"],
		[1.0/5,"cx","marmor2e"],
		[1.0/2,"cx","marmor2f"],
		[1.0,"cx","marmor2g"],
		[1.0/10,"cx","marmor2h"],
		[1.0,"cx","marmor3a"],
		[1.0,"cx","marmor3b"],
		[1.0,"cx","marmor3c"],
		[1.0,"cx","marmor3d"],
		[1.0,"cx","marmor3g"],
		[1.0,"cx","marmor4c"],
		[1.0,"cx","marmor4d"],
		[1.0/3,"cx","marmor4e"],
		[1.0,"cx","marmor4g"],
		[1.0/1.2,"cx","marmor4h"],
		[1.0/10,"cx","marmor5b"],
		[1.0,"cx","marmor5c"],
		[1.0,"cx","marmor5f"],
		[1.0,"cx","marmor5g"],
		[1.0,"cx","marmor5h"],
		[1.0/3,"cx","marmor5e"],
		[1.0,"cx","marmor6g"],
		[1.0,"cx","marmor6h"],
		[1.0,"cx","marmor7a"],
		[1.0,"cx","marmor7b"],
		[1.0,"cx","marmor7c"],
		[1.0,"cx","marmor7d"],
		[1.0,"cx","marmor7e"],
		[1.0,"cx","marmor7f"],
		[1.0,"cx","marmor7g"],
		[1.0,"cx","marmor7h"],
		[1.0,"cx","marmor8a"],
		[1.0,"cx","marmor8b"],
		[1.0,"cx","marmor8c"],
		[1.0,"cx","marmor8d"],
		[1.0,"cx","marmor8e"],
		[1.0,"cx","marmor8f"],
		[1.0,"cx","marmor8g"],
		[1.0,"cx","marmor8h"],
		[1.0/3,"cx","marmor9a"],
		[1.0/5,"cx","marmor9b"],
		[1.0,"cx","marmor9c"],
		[1.0,"cx","marmor9d"],
		[1.0/10,"cx","marmor9e"],
		[1.0/9,"cx","marmor9f"],
		[1.0/12,"cx","marmor9g"],
		[1.0/3,"cx","marmor9h"],
		[1.0,"cx","sarmor1a"],
		[1.0,"cx","sarmor1c"],
		[1.0,"cx","sarmor1d"],
		[1.0,"cx","sarmor1e"],
		[1.0,"cx","sarmor1f"],
		[1.0,"cx","sarmor1g"],
		[1.0,"cx","sarmor2a"],
		[1.0,"cx","sarmor2b"],
		[1.0,"cx","sarmor2c"],
		[1.0/32,"cx","mbody1a"],
		[1.0/4,"cx","mbody1b"],
		[1.0/8,"cx","mbody1c"],
		[1.0,"cx","mbody1d"],
		[1.0/5,"cx","mbody1e"],
		[1.0,"cx","mbody1f"],
		[1.0/3,"cx","mbody1g"],
		[1.0,"cx","mbody1h"],
		[1.0,"cx","mbody2a"],
		[1.0,"cx","mbody2d"],
		[1.0,"cx","mbody2e"],
		[1.0/20,"cx","mbody2f"],
		[1.0/12,"cx","mbody3a"],
		[1.0/16,"cx","mbody3b"],
		[1.0/48,"cx","mbody3d"],
		[1.0/72,"cx","mbody3e"],
		[1.0/1.2,"cx","mbody4a"],
		[1.0/5,"cx","mbody4e"],
		[1.0,"cx","mbody4g"],
		[1.0,"cx","mbody4d"],
		[1.0/10,"cx","mbody4h"],
		[1.0/10,"cx","mbody5a"],
		[1.0/10,"cx","mbody5c"],
		[1.0/6,"cx","mbody5d"],
		[1.0/10,"cx","mbody6a"],
		[1.0,"cx","sbody1d"],
		[1.0,"cx","sbody1e"],
		[1.0/12,"cxbundle","pinkb"],
		[1.0/40,"cxbundle","blackw"],
	],
	"cosmo1":[
		[1,"cx","mmakeup0"],
	],
	"cosmo2":[
	],
	"cosmo3":[
	],
}

for n,nm in [[1,25],[2,25],[3,25],[4,25],[5,22]]:
	for num in range(nm):
		if "%s%.2d"%(n,num) in ["122","203","404"]: continue
		drops["cosmo2"].append([1,"cx","hairdo%s%.2d"%(n,num)])

drops["cosmo2"].append([1.0/2,"cx","hairdo122"])
drops["cosmo2"].append([1.0/3,"cx","hairdo404"])
drops["cosmo2"].append([1.0/10,"cx","hairdo203"])

for n,nm in [[1,16],[2,25],[3,24],[4,8]]:
	for num in range(nm):
		if "%s%.2d"%(n,num) in ["100","114","115","102","106","113","310","309","318","400","405"]: continue
		drops["cosmo3"].append([1,"cx","hat%s%.2d"%(n,num)])

drops["cosmo3"].append([1.0/2,"cx","hat106"])
drops["cosmo3"].append([1.0/3,"cx","hat310"])
drops["cosmo3"].append([1.0/5,"cx","hat102"])
drops["cosmo3"].append([1.0/8,"cx","hat318"])
drops["cosmo3"].append([1.0/10,"cx","hat113"])
drops["cosmo3"].append([1.0/12,"cx","hat309"])
drops["cosmo3"].append([1.0/12,"cx","hat400"])
drops["cosmo3"].append([1.0/12,"cx","hat405"])

for key in drops.keys():
	if key.find(",")!=-1:
		t=drops[key]
		del drops[key]
		key=key.split(","); key.sort()
		key=",".join(key)
		drops[key]=t

for name in items:
	if not items[name].get("ignore") and not items[name].get("exclusive"):
		if items[name].get("grades") and (items[name].get("upgrade") and items[name]["grades"][2]<8 or items[name].get("compound") and items[name]["grades"][2]<3):
			drops["glitch"].append([0.1,name])
		elif items[name].get("grades") and items[name]["grades"][2]==0:
			drops["glitch"].append([0.1,name])
		elif items[name].get("grades") and items[name]["grades"][1]==0:
			drops["glitch"].append([0.25,name])
		else:
			drops["glitch"].append([1,name])

for name in items:
	if "g" not in items[name]:
		import logging
		logging.error(name)
	if not items[name].get("ignore") and not items[name].get("exclusive"):
		if items[name].get("grades") and (items[name].get("upgrade") and items[name]["grades"][2]<8 or items[name].get("compound") and items[name]["grades"][2]<3) or items[name].get("g",0)>5000000:
			drops["lglitch"].append([0.01,name])
		elif items[name].get("grades") and items[name]["grades"][2]==0:
			drops["lglitch"].append([0.05,name])
		elif items[name].get("grades") and items[name]["grades"][1]==0 or items[name].get("g",0)>50000:
			drops["lglitch"].append([0.1,name])
		else:
			drops["lglitch"].append([1,name])

drops["glitch"].append([5,"glitch",2])
drops["monsters"]["cutebee"]=[[1,"open","lglitch"]]
drops["monsters"]["cutebee"].append([1,"funtoken"])
#drops["candy0"]=copy.deepcopy(drops["gem0"])
#drops["candy0"].append([2,"phelmet"])
#drops["candy1"]=copy.deepcopy(drops["gem1"])
#drops["candy1"].append([0.32,"phelmet"])
