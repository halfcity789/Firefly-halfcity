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
		imgurl:
			"https://bu.dusays.com/2026/03/24/69c1e38ac1846.jpg",
		desc: "今天我也要学习吗",
		siteurl: "https://www.xinghuisama.top",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "Lingkaの宝藏之地",
		imgurl:
			"https://bu.dusays.com/2026/06/12/6a2c1cb4f2089.jpg",
		desc: "一个在硬件、MCU、FPGA和ARM Linux SoC之间来回折腾的开发者，目标是让每一块板子都乖乖跑起来。",
		siteurl: "https://www.lingkalab.top/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "阿的宝藏之地",
		imgurl:
			"https://bu.dusays.com/2026/06/20/6a361fc5c68ff.jpg",
		desc: "记录项目、数学思考与杂谈。",
		siteurl: "https://nothing-new.icu",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
		enabled: true, // 是否启用
	},
	{
		title: "米白 の 宝藏之地",
		imgurl:
			"https://bu.dusays.com/2026/05/10/69fff19d7b60d.jpg",
		desc: "在代码、二次元与摄影间穿梭的普通人。近期正埋头于 修图与全栈开发。",
		siteurl: "https://www.mibai.xyz/",
		tags: ["Blog"],
		weight: 10, // 权重，数字越大排序越靠前
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
