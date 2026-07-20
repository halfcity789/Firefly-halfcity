import type { FriendLink, FriendsPageConfig } from "../types/friendsConfig";

// 可以在src/content/spec/friends.md中编写友链页面下方的自定义内容

// 友链页面配置
export const friendsPageConfig: FriendsPageConfig = {
	// 页面标题，如果留空则使用 i18n 中的翻译
	title: "友链",

	// 页面描述文本，如果留空则使用 i18n 中的翻译
	description: "这里是我的朋友们，欢迎互相访问交流",

	// 是否显示底部自定义内容（friends.mdx 中的内容）
	showCustomContent: true,

	// 是否显示评论区，需要先在commentConfig.ts启用评论系统
	showComment: true,

	// 是否开启随机排序配置，如果开启，就会忽略权重，构建时进行一次随机排序
	randomizeSort: false,
};

// 友链配置
export const friendsConfig: FriendLink[] = [
	{
		title: "XingHuiSamaの宝藏之地",
		imgurl:"https://bu.dusays.com/2026/03/24/69c1e38ac1846.jpg",
		desc: "今天我也要学习吗",
		siteurl: "https://www.xinghuisama.top",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "Lingkaの宝藏之地",
		imgurl: "https://bu.dusays.com/2026/06/12/6a2c1cb4f2089.jpg",
		desc: "一个在硬件、MCU、FPGA和ARM Linux SoC之间来回折腾的开发者,目标是让每一块板子都乖乖跑起来。",
		siteurl: "https://www.lingkalab.top/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "阿的宝藏之地",
		imgurl:"https://bu.dusays.com/2026/06/20/6a361fc5c68ff.jpg",
		desc: "记录项目、数学思考与杂谈。",
		siteurl: "https://nothing-new.icu",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "流欺の博客",
		imgurl:"https://tc.lqay.cn/LightPicture/2026/03/5f64e0f0f361e19c.png",
		desc: "嗯对就是个博客",
		siteurl: "https://blog.lqay.cn",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "wangxinyang",
		imgurl:"https://wangxinyang.top/avatar.png",
		desc: "个人博客 / 学习交流 / 生活日常",
		siteurl: "https://wangxinyang.top",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "bbb-lsy07",
		imgurl:"https://blog.tsoo.net/upload/lsyb.png",
		desc: "科技激荡人文，洞见智慧本真。",
		siteurl: "https://blog.tsoo.net",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "Eric - Termina的博客",
		imgurl:"https://assets.ericterminal.com/logo-transparent.png",
		desc: "刃は鞘に、心は花に",
		siteurl: "https://blog.ericterminal.com",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "狐狐's Blog",
		imgurl: "https://blog.foxnature.net/profile.png",
		desc: "我不是狐，却借狐名；你若唤我狐狐，我便答应",
		siteurl: "https://blog.foxnature.net/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "Hello I'm 0o酱",
		imgurl: "https://image.im0o.top/files/202112021204213.jpg",
		desc: "光阴如梦，昨日随风",
		siteurl: "https://blog.im0o.top/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "Eliauk's Blog",
		imgurl: "https://img.eliauk312.top/avatar/default-avatar.jpg",
		desc: "一方天地，记录代码、生活和偶尔的奇思妙想。",
		siteurl: "https://eliauk312.top/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "补络阁",
		imgurl: "https://oss.tuf3i.cc/blog/profile/avatar.png",
		desc: "咕咕嘎嘎，咕咕嘎嘎...",
		siteurl: "https://blog.tuf3i.cc",
		tags: ["Blog"],
		weight: 50, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "萑澈的寒舍",
		imgurl: "https://gastigado.cnies.org/d/elements/hxcn_transparent_240.png",
		desc: "就是为了这点醋才包的这顿饺子",
		siteurl: "https://hxcn.cnies.org/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "RAGNote",
		imgurl: "https://ragnote.top/Avatar.png",
		desc: "Life is code. I will debug it.",
		siteurl: "https://ragnote.top/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "SengokuCola的博客",
		imgurl: "https://lsky.nibutupaopao.top/i/2026/07/09/6a4fc40211f69.png",
		desc: "随着风的轨迹 在那耀眼的午后",
		siteurl: "https://home.nibutupaopao.top",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "MeTの主页",
		imgurl: "https://met6.top/res/logo.png",
		desc: "Stay Hungry. Stay Foolish. 求知若渴，大智若愚。",
		siteurl: "https://met6.top/",
		tags: ["Blog"],
		weight: 50, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	}
];

// 获取启用的友链并进行排序
export const getEnabledFriends = (): FriendLink[] => {
	const friends = friendsConfig.filter((friend) => friend.enabled);

	if (friendsPageConfig.randomizeSort) {
		return friends.sort(() => Math.random() - 0.5);
	}

	return friends.sort((a, b) => b.weight - a.weight);
};
